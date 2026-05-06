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


def is_non_vulnerable_label(label_name: str) -> bool:
    return normalize_label_name(label_name) in NON_VULNERABLE_LABELS


class DetectorRuntime:
    """Load a trained detector once and reuse it for repeated inference calls."""

    def __init__(
        self,
        model_dir: Path,
        prompt_text: str | None = None,
        max_length: int | None = None,
        top_k: int = 3,
    ) -> None:
        self.model_dir = model_dir.resolve()
        if not self.model_dir.exists():
            raise ValueError(f"model dir does not exist: {self.model_dir}")

        self.metadata = load_metadata(self.model_dir)
        self.target_vuln_type = str(self.metadata.get("target_vuln_type") or "").strip()
        if not self.target_vuln_type:
            raise ValueError("model metadata is missing target_vuln_type")

        self.prompt_text = prompt_text
        if self.prompt_text is None:
            self.prompt_text = self.metadata.get("prompt_text")
        self.max_length = max_length or int(self.metadata.get("max_length", 256))
        self.top_k = max(1, top_k)

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_dir)
        self.device = choose_device()
        self.model.to(self.device)
        self.model.eval()

        label_map = self.metadata.get("label_map") or {}
        self.id_to_label = {int(index): label for label, index in label_map.items()}
        if not self.id_to_label:
            config_labels = getattr(self.model.config, "id2label", None) or {}
            self.id_to_label = {int(index): str(label) for index, label in config_labels.items()}
        if not self.id_to_label:
            raise ValueError("label map is missing from metadata and model config")

    def _predict_probabilities(self, source: str) -> tuple[dict[str, Any], list[float]]:
        rendered = render_text(source, self.prompt_text, self.tokenizer.mask_token or "<mask>")
        encoded = self.tokenizer(
            rendered,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )
        encoded = {key: value.to(self.device) for key, value in encoded.items()}

        start = time.perf_counter()
        with torch.no_grad():
            outputs = self.model(**encoded)
            probs = torch.softmax(outputs.logits, dim=-1).squeeze(0)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return {
            "elapsed_ms": elapsed_ms,
            "device": self.device,
            "rendered": rendered,
        }, probs.detach().cpu().tolist()

    def infer(self, source: str) -> dict[str, Any]:
        meta, probs = self._predict_probabilities(source)

        ranked = sorted(
            (
                {
                    "token": self.id_to_label[index],
                    "score": round(float(score), 4),
                }
                for index, score in enumerate(probs)
            ),
            key=lambda item: item["score"],
            reverse=True,
        )

        top_entry = ranked[0]
        predicted_label_name = str(top_entry["token"])
        label = infer_label(predicted_label_name)
        return {
            "label": label,
            "label_name": predicted_label_name,
            "confidence": top_entry["score"],
            "vuln_type": "" if label == "nonVulnerable" else self.target_vuln_type,
            "matched_token": "nonVulnerable" if label == "nonVulnerable" else "vulnerable",
            "top_k": ranked[: self.top_k],
            "scores": {item["token"]: item["score"] for item in ranked},
            "elapsed_ms": meta["elapsed_ms"],
            "device": meta["device"],
        }

    def vulnerable_score(self, source: str) -> float:
        _, probs = self._predict_probabilities(source)
        vuln_score = 0.0
        for index, score in enumerate(probs):
            label_name = self.id_to_label[index]
            if not is_non_vulnerable_label(str(label_name)):
                vuln_score += float(score)
        return vuln_score

    def tokenize(self, source: str, truncation: bool = False) -> list[int]:
        rendered = render_text(source, self.prompt_text, self.tokenizer.mask_token or "<mask>")
        encoded = self.tokenizer(
            rendered,
            truncation=truncation,
            padding=False,
            max_length=self.max_length if truncation else None,
            return_tensors=None,
        )
        return list(encoded["input_ids"])


def main() -> None:
    args = parse_args()
    source = sys.stdin.read()
    if not source.strip():
        raise ValueError("empty source from stdin")

    runtime = DetectorRuntime(
        model_dir=args.model_dir,
        prompt_text=args.prompt_text,
        max_length=args.max_length,
        top_k=args.top_k,
    )
    # 当前推理脚本直接读取分类头输出概率，而不是再走额外的启发式关键词判断。
    result = runtime.infer(source)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
