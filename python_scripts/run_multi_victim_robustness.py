from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import torch

PROJECT_ROOT = Path(__file__).resolve().parent
DIP_ROOT = PROJECT_ROOT / "DIP-Attack"
if str(DIP_ROOT) not in sys.path:
    sys.path.insert(0, str(DIP_ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from data.loader import load_dataset
from evaluation.metrics import compute_codebleu_approx
from infer_detector import DetectorRuntime
from models.tokenizer import SolidityTokenizer
from models.wrapper import MODEL_NAMES, PyTorchVictimModel
from run_dip_attack import (
    CodeBERTVictimAdapter,
    VisibleWindowDIPAttacker,
    count_visible_token_changes,
    round4,
    visible_line_limit,
)

VICTIM_MODEL_KEYS = ["codebert", "AME", "GPSCVul", "ConvMHSA", "Clear"]
VICTIM_DISPLAY = {
    "codebert": "CodeBERT",
    "AME": "AME",
    "GPSCVul": "GPSCVul",
    "ConvMHSA": "ConvMHSA",
    "Clear": "Clear",
}
TARGET_MAP = {
    "reentrancy": "reentrancy",
    "arithmetic": "integer_overflow",
}
CACHE_VERSION = "v1"
CACHE_DIR = PROJECT_ROOT / "victim_cache"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_dir", type=Path, required=True)
    parser.add_argument("--prompt_text")
    parser.add_argument("--target_vuln_type", required=True)
    parser.add_argument("--victim_models", required=True)
    parser.add_argument("--variants", type=int, default=1)
    parser.add_argument("--max_queries", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def parse_contracts(stdin_text: str) -> list[dict[str, str]]:
    payload = json.loads(stdin_text)
    contracts = payload.get("contracts")
    if not isinstance(contracts, list):
        raise ValueError("contracts payload is missing")
    result: list[dict[str, str]] = []
    for item in contracts:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "id": str(item.get("id") or ""),
                "name": str(item.get("name") or ""),
                "processedSource": str(item.get("processedSource") or ""),
            }
        )
    return result


def cache_path(model_name: str, vuln_type: str) -> Path:
    return CACHE_DIR / f"{model_name.lower()}-{vuln_type}-{CACHE_VERSION}.pt"


def save_pytorch_victim_model(model_name: str, vuln_type: str, model: PyTorchVictimModel) -> None:
    if model.tokenizer is None or model.net is None or not model.trained:
        return
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model_name": model_name,
            "vuln_type": vuln_type,
            "tokenizer": {
                "max_vocab": model.tokenizer.max_vocab,
                "max_len": model.tokenizer.max_len,
                "word2idx": model.tokenizer.word2idx,
                "idx2word": model.tokenizer.idx2word,
                "vocab_size": model.tokenizer.vocab_size,
            },
            "state_dict": model.net.state_dict(),
        },
        cache_path(model_name, vuln_type),
    )


def load_cached_pytorch_victim_model(model_name: str, vuln_type: str) -> PyTorchVictimModel | None:
    path = cache_path(model_name, vuln_type)
    if not path.exists():
        return None
    payload = torch.load(path, map_location="cpu")
    if payload.get("model_name") != model_name or payload.get("vuln_type") != vuln_type:
        return None

    model = PyTorchVictimModel(model_name, vuln_type)
    tok_info = payload["tokenizer"]
    tokenizer = SolidityTokenizer(
        max_vocab=int(tok_info["max_vocab"]),
        max_len=int(tok_info["max_len"]),
    )
    tokenizer.word2idx = {str(k): int(v) for k, v in tok_info["word2idx"].items()}
    tokenizer.idx2word = {int(k): str(v) for k, v in tok_info["idx2word"].items()}
    tokenizer.vocab_size = int(tok_info["vocab_size"])
    model.tokenizer = tokenizer

    arch_cls = model.ARCH_MAP[model_name]
    model.net = arch_cls(vocab_size=tokenizer.vocab_size, extra_dim=model.extra_dim)
    model.net.load_state_dict(payload["state_dict"])
    model.net.eval()
    model.trained = True
    return model


def train_or_load_victim_model(model_name: str, vuln_type: str) -> tuple[PyTorchVictimModel, bool]:
    cached = load_cached_pytorch_victim_model(model_name, vuln_type)
    if cached is not None:
        return cached, True

    vuln_contracts, safe_contracts = load_dataset(DIP_ROOT / "data", vuln_type, prefer_curated=True)
    # 控制首次接入的训练成本，先按上限裁到可接受范围。
    train_vuln = vuln_contracts[:64]
    train_safe = safe_contracts[:64]
    model = PyTorchVictimModel(model_name, vuln_type)
    epochs = 50 if model_name == "Clear" else 30
    lr = 2e-3 if model_name == "Clear" else 1e-3
    model.train_model(train_vuln + train_safe, [1] * len(train_vuln) + [0] * len(train_safe), epochs=epochs, lr=lr)
    save_pytorch_victim_model(model_name, vuln_type, model)
    return model, False


def infer_generic_victim(victim_model, code: str, mapped_vuln_type: str) -> dict[str, Any]:
    vuln_score = float(victim_model.predict_score(code))
    is_vuln = int(victim_model(code)) == 1
    return {
        "label": "vulnerable" if is_vuln else "nonVulnerable",
        "confidence": round4(vuln_score if is_vuln else (1.0 - vuln_score)),
        "vulnScore": round4(vuln_score),
        "vulnType": mapped_vuln_type if is_vuln else "",
        "elapsedMs": 0,
    }


def approx_visible_line_end(code: str, max_lines: int = 24) -> int:
    return max(1, min(len(code.split("\n")), max_lines))


def approx_visible_token_changes(original: str, adversarial: str, visible_line_end: int) -> tuple[int, int]:
    token_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|==|!=|<=|>=|&&|\|\||[{}()[\].,;:+\-*/%<>=!]")
    visible_original = "\n".join(original.split("\n")[:visible_line_end])
    visible_adversarial = "\n".join(adversarial.split("\n")[:visible_line_end])
    orig_tokens = token_pattern.findall(visible_original)
    adv_tokens = token_pattern.findall(visible_adversarial)
    window = max(len(orig_tokens), len(adv_tokens), 1)
    changed = 0
    for idx in range(window):
        left = orig_tokens[idx] if idx < len(orig_tokens) else None
        right = adv_tokens[idx] if idx < len(adv_tokens) else None
        if left != right:
            changed += 1
    return changed, window


def evaluate_victim(
    victim_key: str,
    display_name: str,
    victim_model,
    contracts: list[dict[str, str]],
    mapped_vuln_type: str,
    variants_per_source: int,
    max_queries: int,
    seed: int,
    cache_hit: bool | None = None,
) -> dict[str, Any]:
    per_contract: list[dict[str, Any]] = []
    total_variants = 0
    attack_successes = 0
    attackable_contracts = 0
    adv_correct = 0
    confidence_drop_sum = 0.0
    queries_sum = 0.0
    perturb_sum = 0.0
    visible_perturb_sum = 0.0
    codebleu_sum = 0.0
    query_budget_hits = 0

    for contract_index, contract in enumerate(contracts):
        source = contract["processedSource"]
        baseline = infer_generic_victim(victim_model, source, mapped_vuln_type)
        attackable = baseline["label"] == "vulnerable"
        row = {
            "baseContractId": contract["id"],
            "contractName": contract["name"],
            "origLabel": baseline["label"],
            "origConfidence": baseline["confidence"],
            "origVulnScore": baseline["vulnScore"],
            "attackable": attackable,
            "skippedReason": "",
            "advTotal": 0,
            "flipped": 0,
            "avgAdvConfidence": 0.0,
            "avgConfDrop": 0.0,
            "avgQueries": 0.0,
            "avgPerturbationRate": 0.0,
            "avgVisiblePerturbationRate": 0.0,
            "avgCodeBLEU": 0.0,
            "queryBudgetHits": 0,
            "bestAttackStrategy": "dip-attack",
            "bestAttackSample": None,
            "byStrategy": {},
        }
        if not attackable:
            row["skippedReason"] = "原始样本未被该受害模型判定为目标漏洞，不进入攻击成功率统计"
            per_contract.append(row)
            continue

        attackable_contracts += 1
        if hasattr(victim_model, "runtime"):
            visible_lines = visible_line_limit(victim_model.runtime, source)
        else:
            # 对非 CodeBERT 受害模型，保持 DIP 的可见窗口攻击流程，但用固定可见行近似它们的输入截断窗口。
            visible_lines = approx_visible_line_end(source)

        best_score = -1.0
        for variant_index in range(variants_per_source):
            attacker = VisibleWindowDIPAttacker(
                vuln_type=mapped_vuln_type,
                visible_line_end=visible_lines,
                max_queries=max_queries,
                seed=seed + contract_index * 31 + variant_index,
            )
            attack_result = attacker.attack(source, victim_model)
            adv_code = attack_result["adv_code"]
            adversarial = infer_generic_victim(victim_model, adv_code, mapped_vuln_type)
            success = adversarial["label"] == "nonVulnerable"
            if hasattr(victim_model, "runtime"):
                visible_changed_tokens, visible_window_tokens = count_visible_token_changes(victim_model.runtime, source, adv_code)
            else:
                visible_changed_tokens, visible_window_tokens = approx_visible_token_changes(source, adv_code, visible_lines)
            perturbation_rate = round4(int(attack_result["perturbation_tokens"]) / max(1, int(attack_result["original_tokens"])))
            visible_perturbation_rate = round4(visible_changed_tokens / max(1, visible_window_tokens))
            codebleu, _ = compute_codebleu_approx([source], [adv_code])
            confidence_drop = round4(max(0.0, float(baseline["confidence"]) - float(adversarial["confidence"])))
            vuln_score_drop = round4(max(0.0, float(baseline["vulnScore"]) - float(adversarial["vulnScore"])))
            query_budget_hit = int(attack_result["queries"]) >= max_queries

            sample = {
                "variantIndex": variant_index + 1,
                "queries": int(attack_result["queries"]),
                "perturbationTokens": int(attack_result["perturbation_tokens"]),
                "originalTokens": int(attack_result["original_tokens"]),
                "perturbationRate": perturbation_rate,
                "visiblePerturbationRate": visible_perturbation_rate,
                "codebleu": round4(codebleu),
                "queryBudgetHit": query_budget_hit,
                "confidenceDrop": confidence_drop,
                "vulnScoreDrop": vuln_score_drop,
                "attackSucceeded": success,
            }

            row["advTotal"] += 1
            row["avgAdvConfidence"] += adversarial["confidence"]
            row["avgConfDrop"] += confidence_drop
            row["avgQueries"] += sample["queries"]
            row["avgPerturbationRate"] += perturbation_rate
            row["avgVisiblePerturbationRate"] += visible_perturbation_rate
            row["avgCodeBLEU"] += round4(codebleu)
            if query_budget_hit:
                row["queryBudgetHits"] += 1
                query_budget_hits += 1

            total_variants += 1
            confidence_drop_sum += confidence_drop
            queries_sum += sample["queries"]
            perturb_sum += perturbation_rate
            visible_perturb_sum += visible_perturbation_rate
            codebleu_sum += round4(codebleu)

            if success:
                row["flipped"] += 1
                attack_successes += 1
            else:
                adv_correct += 1

            score = vuln_score_drop + (1000 if success else 0)
            if score > best_score:
                best_score = score
                row["bestAttackSample"] = sample

        if row["advTotal"] > 0:
            denom = float(row["advTotal"])
            row["avgAdvConfidence"] = round4(row["avgAdvConfidence"] / denom)
            row["avgConfDrop"] = round4(row["avgConfDrop"] / denom)
            row["avgQueries"] = round4(row["avgQueries"] / denom)
            row["avgPerturbationRate"] = round4(row["avgPerturbationRate"] / denom)
            row["avgVisiblePerturbationRate"] = round4(row["avgVisiblePerturbationRate"] / denom)
            row["avgCodeBLEU"] = round4(row["avgCodeBLEU"] / denom)
            row["byStrategy"] = {
                "dip-attack": {
                    "total": row["advTotal"],
                    "attackSuccesses": row["flipped"],
                    "attackSuccessRate": round4(row["flipped"] / denom),
                    "avgConfidenceDrop": row["avgConfDrop"],
                    "avgQueries": row["avgQueries"],
                    "avgPerturbationRate": row["avgPerturbationRate"],
                    "avgVisiblePerturbationRate": row["avgVisiblePerturbationRate"],
                    "avgCodeBLEU": row["avgCodeBLEU"],
                    "queryBudgetHits": row["queryBudgetHits"],
                }
            }
        per_contract.append(row)

    orig_accuracy = 1.0 if attackable_contracts > 0 else 0.0
    adv_accuracy = adv_correct / max(total_variants, 1)
    attack_success_rate = attack_successes / max(total_variants, 1)
    accuracy_drop_rate = max(0.0, orig_accuracy - adv_accuracy)
    avg_perturb = perturb_sum / max(total_variants, 1)
    avg_visible = visible_perturb_sum / max(total_variants, 1)
    visibility_warning = ""
    if avg_perturb >= 0.2 and avg_visible <= 0.02:
        visibility_warning = "该受害模型下的攻击改动大多未转化为模型可见扰动，当前 0% 结果更应解释为攻击未有效命中模型输入。"

    return {
        "victimModel": victim_key,
        "displayName": display_name,
        "attackMethod": "dip-attack",
        "supported": True,
        "cacheHit": cache_hit,
        "targetVulnType": mapped_vuln_type,
        "attackableContracts": attackable_contracts,
        "totalAdversarial": total_variants,
        "attackSuccesses": attack_successes,
        "attackSuccessRate": round4(attack_success_rate),
        "origAccuracy": round4(orig_accuracy),
        "advAccuracy": round4(adv_accuracy),
        "accuracyDropRate": round4(accuracy_drop_rate),
        "avgConfidenceDrop": round4(confidence_drop_sum / max(total_variants, 1)),
        "avgQueries": round4(queries_sum / max(total_variants, 1)),
        "avgPerturbationRate": round4(avg_perturb),
        "avgVisiblePerturbationRate": round4(avg_visible),
        "avgCodeBLEU": round4(codebleu_sum / max(total_variants, 1)),
        "queryBudgetHits": query_budget_hits,
        "visibilityWarning": visibility_warning,
        "perStrategy": [
            {
                "strategy": "dip-attack",
                "totalVariants": total_variants,
                "attackSuccesses": attack_successes,
                "attackSuccessRate": round4(attack_success_rate),
                "avgConfidenceDrop": round4(confidence_drop_sum / max(total_variants, 1)),
                "avgQueries": round4(queries_sum / max(total_variants, 1)),
                "avgPerturbationRate": round4(avg_perturb),
                "avgVisiblePerturbationRate": round4(avg_visible),
                "avgCodeBLEU": round4(codebleu_sum / max(total_variants, 1)),
                "queryBudgetHits": query_budget_hits,
            }
        ],
        "perContract": per_contract,
    }


def main() -> None:
    args = parse_args()
    contracts = parse_contracts(sys.stdin.read())
    if not contracts:
        raise ValueError("empty contracts payload")

    target_vuln_type = str(args.target_vuln_type).strip()
    requested_models = [item.strip() for item in args.victim_models.split(",") if item.strip()]

    runtime = DetectorRuntime(
        model_dir=args.model_dir,
        prompt_text=args.prompt_text,
        top_k=3,
    )

    victim_results: list[dict[str, Any]] = []
    mapped_vuln_type = TARGET_MAP.get(target_vuln_type, "")

    for victim_key in requested_models:
        if victim_key == "codebert":
            codebert_victim = CodeBERTVictimAdapter(runtime)
            codebert_victim.runtime = runtime  # type: ignore[attr-defined]
            victim_results.append(
                evaluate_victim(
                    victim_key=victim_key,
                    display_name=VICTIM_DISPLAY[victim_key],
                    victim_model=codebert_victim,
                    contracts=contracts,
                    mapped_vuln_type=target_vuln_type,
                    variants_per_source=max(1, args.variants),
                    max_queries=max(1, args.max_queries),
                    seed=args.seed,
                )
            )
            continue

        if victim_key not in MODEL_NAMES:
            victim_results.append(
                {
                    "victimModel": victim_key,
                    "displayName": victim_key,
                    "attackMethod": "dip-attack",
                    "supported": False,
                    "skippedReason": "未知受害模型",
                }
            )
            continue

        if mapped_vuln_type == "":
            victim_results.append(
                {
                    "victimModel": victim_key,
                    "displayName": VICTIM_DISPLAY[victim_key],
                    "attackMethod": "dip-attack",
                    "supported": False,
                    "skippedReason": f"当前目标漏洞类型 {target_vuln_type} 暂未接入该受害模型",
                }
            )
            continue

        model, cache_hit = train_or_load_victim_model(victim_key, mapped_vuln_type)
        victim_results.append(
            evaluate_victim(
                victim_key=victim_key,
                display_name=VICTIM_DISPLAY[victim_key],
                victim_model=model,
                contracts=contracts,
                mapped_vuln_type=mapped_vuln_type,
                variants_per_source=max(1, args.variants),
                max_queries=max(1, args.max_queries),
                seed=args.seed,
                cache_hit=cache_hit,
            )
        )

    print(
        json.dumps(
            {
                "targetVulnType": target_vuln_type,
                "attackMethod": "dip-attack",
                "attackPipeline": [
                    "scope-aware-variable-renaming",
                    "gradient-estimated-position-selection",
                    "dead-code-insertion",
                ],
                "victimResults": victim_results,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
