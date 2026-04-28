from __future__ import annotations

# 推理流程概述：
# 1. 读取训练阶段保存的模型目录与 metadata，恢复目标漏洞类型、标签映射和默认提示模板；
# 2. 将待测智能合约源码按训练时相同的提示模板渲染并送入 tokenizer；
# 3. 调用分类模型输出二分类概率，生成标签、置信度、目标漏洞类型和 top-k 结果；
# 4. 将结构化推理结果返回给后端检测与鲁棒性模块复用。

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


NON_VULNERABLE_LABELS = {
    "benign",
    "clean",
    "non_vulnerable",
    "non-vulnerable",
    "nonvulnerable",
    "safe",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_dir", type=Path, required=True)
    parser.add_argument("--prompt_text")
    parser.add_argument("--max_length", type=int)
    parser.add_argument("--top_k", type=int, default=3)
    return parser.parse_args()


def choose_device() -> str:
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def render_text(source: str, prompt_text: str | None, mask_token: str) -> str:
    # 推理阶段复用训练时相同的模板渲染方式，避免训练/检测输入分布不一致。
    if not prompt_text:
        return source
    rendered = prompt_text.replace("[X]", source)
    if "[MASK]" in rendered:
        rendered = rendered.replace("[MASK]", mask_token)
    return rendered


def load_metadata(model_dir: Path) -> dict[str, Any]:
    metadata_path = model_dir / "metadata.json"
    if not metadata_path.exists():
        raise ValueError(f"metadata.json not found in model dir: {model_dir}")
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def normalize_label_name(label_name: str) -> str:
    return label_name.strip().lower().replace(" ", "_")


def infer_label(label_name: str) -> str:
    if normalize_label_name(label_name) in NON_VULNERABLE_LABELS:
        return "nonVulnerable"
    return "vulnerable"


def main() -> None:
    args = parse_args()
    source = sys.stdin.read()
    if not source.strip():
        raise ValueError("empty source from stdin")

    model_dir = args.model_dir.resolve()
    if not model_dir.exists():
        raise ValueError(f"model dir does not exist: {model_dir}")

    metadata = load_metadata(model_dir)
    # 检测模块优先使用模型训练时写入的元数据，保证目标漏洞类型和默认模板可追溯。
    target_vuln_type = str(metadata.get("target_vuln_type") or "").strip()
    if not target_vuln_type:
        raise ValueError("model metadata is missing target_vuln_type")
    prompt_text = args.prompt_text
    if prompt_text is None:
        prompt_text = metadata.get("prompt_text")
    max_length = args.max_length or int(metadata.get("max_length", 256))

    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    device = choose_device()
    model.to(device)
    model.eval()

    label_map = metadata.get("label_map") or {}
    id_to_label = {int(index): label for label, index in label_map.items()}
    if not id_to_label:
        config_labels = getattr(model.config, "id2label", None) or {}
        id_to_label = {int(index): str(label) for index, label in config_labels.items()}
    if not id_to_label:
        raise ValueError("label map is missing from metadata and model config")

    rendered = render_text(source, prompt_text, tokenizer.mask_token or "<mask>")
    # 当前推理脚本直接读取分类头输出概率，而不是再走额外的启发式关键词判断。
    encoded = tokenizer(
        rendered,
        truncation=True,
        padding="max_length",
        max_length=max_length,
        return_tensors="pt",
    )
    encoded = {key: value.to(device) for key, value in encoded.items()}

    start = time.perf_counter()
    with torch.no_grad():
        outputs = model(**encoded)
        probs = torch.softmax(outputs.logits, dim=-1).squeeze(0)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    ranked = sorted(
        (
            {
                "token": id_to_label[index],
                "score": round(float(score), 4),
            }
            for index, score in enumerate(probs.detach().cpu().tolist())
        ),
        key=lambda item: item["score"],
        reverse=True,
    )

    top_entry = ranked[0]
    predicted_label_name = str(top_entry["token"])
    # 输出中同时保留二分类结论、目标漏洞类型和 top-k 概率，供检测页与鲁棒性评估复用。
    result = {
        "label": infer_label(predicted_label_name),
        "label_name": predicted_label_name,
        "confidence": top_entry["score"],
        "vuln_type": "" if infer_label(predicted_label_name) == "nonVulnerable" else target_vuln_type,
        "matched_token": "nonVulnerable" if infer_label(predicted_label_name) == "nonVulnerable" else "vulnerable",
        "top_k": ranked[: max(1, args.top_k)],
        "scores": {item["token"]: item["score"] for item in ranked},
        "elapsed_ms": elapsed_ms,
        "device": device,
    }
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
