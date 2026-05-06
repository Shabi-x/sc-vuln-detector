from __future__ import annotations

# DIP 鲁棒性评估流程概述：
# 1. 复用当前训练好的漏洞检测模型作为受害模型，统一走与检测模块相同的提示渲染和分类推理逻辑；
# 2. 将 DIP 攻击约束到模型实际可见的输入窗口内，优先修改会进入模型截断范围的代码区域；
# 3. 输出攻击成败、查询成本、可见扰动率、代码相似性与查询上限命中等诊断信息，供后端统一评估与展示。

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
DIP_ROOT = PROJECT_ROOT / "DIP-Attack"
if str(DIP_ROOT) not in sys.path:
    sys.path.insert(0, str(DIP_ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks.dip_attack import DIPAttacker, _rename_score
from evaluation.metrics import compute_codebleu_approx
from infer_detector import DetectorRuntime
from utils.solidity_utils import (
    basic_syntax_check,
    count_tokens,
    find_user_defined_vars,
    find_var_scope,
    get_insertable_positions,
    insert_at_line,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_dir", type=Path, required=True)
    parser.add_argument("--prompt_text")
    parser.add_argument("--max_length", type=int)
    parser.add_argument("--variants", type=int, default=1)
    parser.add_argument("--max_queries", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def round4(value: float) -> float:
    return round(float(value), 4)


class CodeBERTVictimAdapter:
    def __init__(self, runtime: DetectorRuntime):
        self.runtime = runtime

    def infer(self, code: str) -> dict[str, Any]:
        return self.runtime.infer(code)

    def __call__(self, code: str) -> int:
        result = self.infer(code)
        return 1 if result["label"] == "vulnerable" else 0

    def predict_score(self, code: str) -> float:
        return self.runtime.vulnerable_score(code)


def visible_line_limit(runtime: DetectorRuntime, code: str, reserve_ratio: float = 0.85) -> int:
    lines = code.split("\n")
    budget = max(32, int(runtime.max_length * reserve_ratio))
    last_visible = len(lines)
    for idx in range(1, len(lines) + 1):
        partial = "\n".join(lines[:idx])
        if len(runtime.tokenize(partial, truncation=False)) > budget:
            last_visible = max(1, idx - 1)
            break
    return last_visible


def count_visible_token_changes(runtime: DetectorRuntime, original: str, adversarial: str) -> tuple[int, int]:
    orig_ids = runtime.tokenize(original, truncation=True)
    adv_ids = runtime.tokenize(adversarial, truncation=True)
    window = max(len(orig_ids), len(adv_ids), 1)
    changed = 0
    for idx in range(window):
        left = orig_ids[idx] if idx < len(orig_ids) else None
        right = adv_ids[idx] if idx < len(adv_ids) else None
        if left != right:
            changed += 1
    return changed, window


class VisibleWindowDIPAttacker(DIPAttacker):
    MAX_INSERTIONS = 8

    def __init__(self, vuln_type: str, visible_line_end: int, max_queries: int = 200, seed: int = 42):
        super().__init__(vuln_type=vuln_type, max_queries=max_queries, seed=seed)
        self.visible_line_end = max(1, visible_line_end)

    def _visible_positions(self, code: str) -> list[int]:
        positions = [p for p in get_insertable_positions(code) if p < self.visible_line_end]
        if positions:
            return positions
        fallback = [p for p in get_insertable_positions(code)]
        return fallback[:1]

    def _rank_positions_by_impact(self, code: str) -> list[int]:
        positions = self._visible_positions(code)
        if not positions:
            return []
        scored = [(p, self.scorer.compute_line_impact(code, p)) for p in positions]
        scored.sort(key=lambda x: x[1], reverse=True)
        top = [p for p, _ in scored[: min(8, len(scored))]]
        return sorted(top)

    def _finite_difference_rerank(self, code: str, positions: list[int], model, budget: int) -> tuple[list[int], int]:
        ranked, used = super()._finite_difference_rerank(code, positions, model, budget)
        front = ranked[: min(8, len(ranked))]
        rest = ranked[min(8, len(ranked)) :]
        return sorted(front) + rest, used

    def _rename_phase(self, code: str) -> str:
        vf = find_user_defined_vars(code)
        if not vf:
            return code
        scored = [(t, n, self._visible_rename_score(code, n, t)) for t, n in vf]
        scored.sort(key=lambda x: x[2], reverse=True)

        result = code
        renamed: set[str] = set()
        for _, old, score in scored:
            if score <= 0 or old in renamed:
                continue
            scopes = [
                (start, end)
                for start, end in find_var_scope(result, old)
                if start < self.visible_line_end
            ]
            if not scopes:
                continue
            role = self._semantic_role(old)
            new = self._generate_semantic_name(role)
            nr = self._scope_aware_rename(result, old, new, scopes)
            if nr != result and basic_syntax_check(nr):
                result = nr
                renamed.add(old)
            if len(renamed) >= self.MAX_RENAME:
                break
        return result

    def _visible_rename_score(self, code: str, var_name: str, var_type: str) -> float:
        lines = code.split("\n")
        for idx, line in enumerate(lines[: self.visible_line_end]):
            if var_name in line:
                return 1.0 + _rename_score(code, var_name, var_type)
        return 0.0

    def _semantic_role(self, name: str) -> str:
        lower = name.lower()
        for role, keywords in {
            "balance": ["balance", "bal", "amount", "amt", "value", "val", "fund"],
            "address": ["addr", "address", "sender", "receiver", "owner", "to", "from"],
            "control": ["flag", "ok", "status", "state", "lock", "guard", "paused"],
            "counter": ["count", "cnt", "num", "index", "idx", "len", "length", "total"],
            "hash": ["hash", "digest", "keccak", "sha"],
            "time": ["time", "timestamp", "ts", "deadline", "expiry", "block"],
            "temp": ["tmp", "temp", "aux", "scratch", "result", "ret"],
        }.items():
            if any(kw in lower for kw in keywords):
                return role
        return "generic"

    def _generate_semantic_name(self, role: str) -> str:
        prefixes = {
            "balance": ["_val", "_v", "_n"],
            "address": ["_a", "_ref", "_p"],
            "control": ["_f", "_s", "_c"],
            "counter": ["_i", "_k", "_j"],
            "hash": ["_h", "_d", "_x"],
            "time": ["_t", "_ts", "_w"],
            "temp": ["_r", "_m", "_q"],
            "generic": ["_u", "_z", "_e"],
        }
        prefix = self.rng.choice(prefixes.get(role, ["_u"]))
        return f"{prefix}{self.rng.randint(100, 99999)}"

    def attack(self, code: str, model) -> dict[str, Any]:
        queries = 0
        orig_tok = count_tokens(code)

        cur = self._rename_phase(code)
        queries += 1
        if model(cur) == 0:
            result = self._success(cur, queries, orig_tok)
            result["visible_line_end"] = self.visible_line_end
            return result

        ranked_pos = self._rank_positions_by_impact(cur)
        if not ranked_pos:
            result = self._fail(code, queries, orig_tok)
            result["visible_line_end"] = self.visible_line_end
            return result

        probe_budget = max(3, int(self.max_queries * self.PROBE_BUDGET_FRAC))
        probe_budget = min(probe_budget, self.max_queries - queries)
        ranked_pos, q_used = self._finite_difference_rerank(cur, ranked_pos, model, probe_budget)
        queries += q_used

        predicates = self._collect_predicates(cur)
        self.rng.shuffle(predicates)

        pos_idx = 0
        n_inserted = 0
        n_syntax_fail = 0
        cur_score = model.predict_score(cur) if hasattr(model, "predict_score") else 1.0
        queries += 1

        while queries < self.max_queries:
            if not ranked_pos:
                break
            if n_syntax_fail > len(ranked_pos) * 3:
                break
            if n_inserted >= self.MAX_INSERTIONS:
                break

            p = ranked_pos[pos_idx % len(ranked_pos)]
            pos_idx += 1
            pred = predicates[n_inserted % len(predicates)]
            stmt = self._gen_require_stmt(pred)
            cand = insert_at_line(cur, p, stmt)

            if not basic_syntax_check(cand):
                n_syntax_fail += 1
                continue
            n_syntax_fail = 0

            queries += 1
            if hasattr(model, "predict_score"):
                new_score = model.predict_score(cand)
                if new_score < 0.5:
                    result = self._success(cand, queries, orig_tok)
                    result["visible_line_end"] = self.visible_line_end
                    return result
                if new_score <= cur_score or self.rng.random() < 0.5:
                    cur = cand
                    cur_score = new_score
                    n_inserted += 1
            else:
                if model(cand) == 0:
                    result = self._success(cand, queries, orig_tok)
                    result["visible_line_end"] = self.visible_line_end
                    return result
                cur = cand
                n_inserted += 1

            if n_inserted > 0 and n_inserted % 10 == 0:
                ranked_pos = self._visible_positions(cur)
                self.rng.shuffle(ranked_pos)
                pos_idx = 0

        result = self._fail(cur, queries, orig_tok)
        result["visible_line_end"] = self.visible_line_end
        return result


def main() -> None:
    args = parse_args()
    source = sys.stdin.read()
    if not source.strip():
        raise ValueError("empty source from stdin")

    runtime = DetectorRuntime(
        model_dir=args.model_dir,
        prompt_text=args.prompt_text,
        max_length=args.max_length,
        top_k=3,
    )
    victim = CodeBERTVictimAdapter(runtime)
    baseline = victim.infer(source)
    baseline_vuln_score = victim.predict_score(source)
    visible_lines = visible_line_limit(runtime, source)
    original_total_tokens = max(1, count_tokens(source))
    original_visible_ids = runtime.tokenize(source, truncation=True)

    variants: list[dict[str, Any]] = []
    vuln_type = runtime.target_vuln_type
    total_variants = max(1, args.variants)

    for index in range(total_variants):
        attacker = VisibleWindowDIPAttacker(
            vuln_type=vuln_type,
            visible_line_end=visible_lines,
            max_queries=max(1, args.max_queries),
            seed=args.seed + index,
        )
        attack_result = attacker.attack(source, victim)
        adv_code = attack_result["adv_code"]
        adv_result = victim.infer(adv_code)
        adv_vuln_score = victim.predict_score(adv_code)
        success = (
            baseline["label"] == "vulnerable"
            and adv_result["label"] == "nonVulnerable"
        )
        perturbation_tokens = int(attack_result["perturbation_tokens"])
        original_tokens = max(1, int(attack_result["original_tokens"]))
        visible_changed_tokens, visible_window_tokens = count_visible_token_changes(runtime, source, adv_code)
        codebleu, _ = compute_codebleu_approx([source], [adv_code])
        query_budget_hit = int(attack_result["queries"]) >= max(1, args.max_queries)

        variants.append(
            {
                "variantIndex": index + 1,
                "success": success,
                "queries": int(attack_result["queries"]),
                "queryBudgetHit": query_budget_hit,
                "perturbationTokens": perturbation_tokens,
                "originalTokens": original_tokens,
                "perturbationRate": round4(perturbation_tokens / original_tokens),
                "visiblePerturbationTokens": visible_changed_tokens,
                "visibleWindowTokens": visible_window_tokens,
                "visiblePerturbationRate": round4(visible_changed_tokens / max(1, visible_window_tokens)),
                "codebleu": round4(codebleu),
                "advCode": adv_code,
                "baseline": {
                    "label": baseline["label"],
                    "confidence": baseline["confidence"],
                    "vulnScore": round4(baseline_vuln_score),
                },
                "adversarial": {
                    "label": adv_result["label"],
                    "confidence": adv_result["confidence"],
                    "vulnScore": round4(adv_vuln_score),
                    "elapsedMs": adv_result["elapsed_ms"],
                },
                "confidenceDrop": round4(
                    max(0.0, float(baseline["confidence"]) - float(adv_result["confidence"]))
                ),
                "vulnScoreDrop": round4(max(0.0, baseline_vuln_score - adv_vuln_score)),
                "visibleLineEnd": int(attack_result.get("visible_line_end", visible_lines)),
            }
        )

    result = {
        "targetVulnType": vuln_type,
        "baseline": {
            "label": baseline["label"],
            "confidence": baseline["confidence"],
            "vulnScore": round4(baseline_vuln_score),
        },
        "attackable": baseline["label"] == "vulnerable",
        "maxLength": runtime.max_length,
        "visibleLineEnd": visible_lines,
        "originalVisibleTokens": len(original_visible_ids),
        "originalTotalTokens": original_total_tokens,
        "variants": variants,
    }
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
