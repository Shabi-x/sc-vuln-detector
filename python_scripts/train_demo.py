from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.optim import AdamW
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup


ALLOWED_SMARTBUGS_CATEGORIES = {
    "reentrancy": "reentrancy",
    "access_control": "access_control",
    "arithmetic": "arithmetic",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--job_id", required=True)
    p.add_argument("--prompt_text", help="硬提示模板内容，可选")
    p.add_argument("--fewshot_size", type=int, default=32)
    p.add_argument("--epochs", type=int, default=5)
    p.add_argument("--batch_size", type=int, default=8)
    p.add_argument("--learning_rate", type=float, default=2e-5)
    p.add_argument("--base_model", default="microsoft/codebert-base")
    p.add_argument("--max_length", type=int, default=256)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--val_ratio", type=float, default=0.2)
    p.add_argument(
        "--dataset_path",
        type=Path,
        help="支持 JSONL 文件或 smartbugs-curated 目录，建议放在 python_scripts/datasets 下",
    )
    p.add_argument(
        "--out_dir",
        type=Path,
        default=Path("python_scripts/demo_outputs"),
        help="用于保存训练指标和模型产物的目录",
    )
    return p.parse_args()


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def load_jsonl_dataset(path: Path) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data.append(json.loads(line))
    return data


def load_smartbugs_dataset(root: Path) -> list[dict[str, Any]]:
    meta_path = root / "vulnerabilities.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for item in meta:
        rel_path = item.get("path")
        if not rel_path:
            continue
        categories = {
            vuln.get("category")
            for vuln in item.get("vulnerabilities", [])
            if isinstance(vuln, dict) and vuln.get("category")
        }
        picked = next((ALLOWED_SMARTBUGS_CATEGORIES[c] for c in ALLOWED_SMARTBUGS_CATEGORIES if c in categories), None)
        if picked is None:
            continue
        source_path = root / rel_path
        if not source_path.exists():
            continue
        rows.append(
            {
                "id": source_path.stem,
                "source": source_path.read_text(encoding="utf-8", errors="ignore"),
                "label_name": picked,
                "vuln_type": picked,
                "path": rel_path,
            }
        )
    return rows


def load_dataset(path: Path) -> list[dict[str, Any]]:
    if path.is_dir():
        if (path / "vulnerabilities.json").exists():
            return load_smartbugs_dataset(path)
        raise ValueError(f"unsupported dataset directory: {path}")
    if path.suffix.lower() == ".jsonl":
        rows = load_jsonl_dataset(path)
        normalized: list[dict[str, Any]] = []
        for row in rows:
            label_name = row.get("vuln_type") or row.get("label_name")
            if not label_name:
                label_value = row.get("label")
                label_name = str(label_value)
            normalized.append(
                {
                    "id": row.get("id"),
                    "source": row.get("source", ""),
                    "label_name": str(label_name),
                    "vuln_type": str(label_name),
                    "path": row.get("path", ""),
                }
            )
        return normalized
    raise ValueError(f"unsupported dataset format: {path}")


def split_dataset(rows: list[dict[str, Any]], fewshot_size: int, val_ratio: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int], dict[str, int]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = str(row["label_name"])
        buckets.setdefault(key, []).append(row)

    train_rows: list[dict[str, Any]] = []
    val_rows: list[dict[str, Any]] = []
    train_counts: dict[str, int] = {}
    val_counts: dict[str, int] = {}

    for key in sorted(buckets):
        bucket = buckets[key]
        random.shuffle(bucket)
        val_count = max(1, int(round(len(bucket) * val_ratio))) if len(bucket) > 2 else 1
        val_count = min(val_count, max(1, len(bucket) - 1))
        bucket_val = bucket[:val_count]
        bucket_train_pool = bucket[val_count:]
        if not bucket_train_pool:
            bucket_train_pool = bucket[-1:]
            bucket_val = bucket[:-1] or bucket[-1:]
        train_take = min(max(1, fewshot_size), len(bucket_train_pool))
        bucket_train = random.sample(bucket_train_pool, train_take)
        train_rows.extend(bucket_train)
        val_rows.extend(bucket_val)
        train_counts[key] = len(bucket_train)
        val_counts[key] = len(bucket_val)

    return train_rows, val_rows, train_counts, val_counts


def build_label_mapping(rows: list[dict[str, Any]]) -> dict[str, int]:
    labels = sorted({str(row["label_name"]) for row in rows})
    return {label: index for index, label in enumerate(labels)}


def render_text(source: str, prompt_text: str | None, mask_token: str) -> str:
    if not prompt_text:
        return source
    rendered = prompt_text.replace("[X]", source)
    if "[MASK]" in rendered:
        rendered = rendered.replace("[MASK]", mask_token)
    return rendered


def choose_device() -> str:
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def compute_metrics(y_true: list[int], y_pred: list[int], label_count: int) -> dict[str, float]:
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    acc = safe_div(correct, len(y_true))

    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []
    for label in range(label_count):
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        f1 = safe_div(2 * precision * recall, precision + recall) if (precision + recall) > 0 else 0.0
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)

    return {
        "acc": acc,
        "precision": float(np.mean(precisions)) if precisions else 0.0,
        "recall": float(np.mean(recalls)) if recalls else 0.0,
        "f1": float(np.mean(f1s)) if f1s else 0.0,
    }


@dataclass
class EncodedExample:
    input_ids: torch.Tensor
    attention_mask: torch.Tensor
    label: torch.Tensor


class SolidityDataset(Dataset[EncodedExample]):
    def __init__(
        self,
        rows: list[dict[str, Any]],
        tokenizer: Any,
        label_map: dict[str, int],
        max_length: int,
        prompt_text: str | None,
    ) -> None:
        self.examples: list[EncodedExample] = []
        mask_token = tokenizer.mask_token or "<mask>"
        for row in rows:
            text = render_text(str(row["source"]), prompt_text, mask_token)
            encoded = tokenizer(
                text,
                truncation=True,
                padding="max_length",
                max_length=max_length,
                return_tensors="pt",
            )
            label = label_map[str(row["label_name"])]
            self.examples.append(
                EncodedExample(
                    input_ids=encoded["input_ids"].squeeze(0),
                    attention_mask=encoded["attention_mask"].squeeze(0),
                    label=torch.tensor(label, dtype=torch.long),
                )
            )

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, index: int) -> dict[str, torch.Tensor]:
        example = self.examples[index]
        return {
            "input_ids": example.input_ids,
            "attention_mask": example.attention_mask,
            "labels": example.label,
        }


def evaluate(model: nn.Module, loader: DataLoader[dict[str, torch.Tensor]], device: str, label_count: int) -> dict[str, float]:
    model.eval()
    losses: list[float] = []
    y_true: list[int] = []
    y_pred: list[int] = []
    with torch.no_grad():
        for batch in loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            outputs = model(**batch)
            losses.append(float(outputs.loss.item()))
            preds = torch.argmax(outputs.logits, dim=-1)
            y_true.extend(batch["labels"].cpu().tolist())
            y_pred.extend(preds.cpu().tolist())
    metrics = compute_metrics(y_true, y_pred, label_count)
    metrics["loss"] = float(np.mean(losses)) if losses else 0.0
    return metrics


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    set_seed(args.seed)

    if args.dataset_path is None:
        raise ValueError("dataset_path is required")

    dataset_rows = load_dataset(args.dataset_path)
    if not dataset_rows:
        raise ValueError("dataset is empty")

    label_map = build_label_mapping(dataset_rows)
    train_rows, val_rows, train_counts, val_counts = split_dataset(dataset_rows, args.fewshot_size, args.val_ratio)
    if not train_rows:
        raise ValueError("training split is empty")
    if not val_rows:
        val_rows = train_rows

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        num_labels=len(label_map),
        id2label={index: label for label, index in label_map.items()},
        label2id=label_map,
    )

    device = choose_device()
    model.to(device)

    train_dataset = SolidityDataset(train_rows, tokenizer, label_map, args.max_length, args.prompt_text)
    val_dataset = SolidityDataset(val_rows, tokenizer, label_map, args.max_length, args.prompt_text)
    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size, shuffle=False)

    optimizer = AdamW(model.parameters(), lr=args.learning_rate)
    total_steps = max(1, len(train_loader) * args.epochs)
    warmup_steps = max(1, total_steps // 10)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)

    best_epoch_summary: dict[str, Any] | None = None
    best_f1 = -1.0
    artifact_dir = args.out_dir / f"{args.job_id}_model"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    metric_history: list[dict[str, Any]] = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        batch_losses: list[float] = []
        for batch in train_loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            optimizer.zero_grad()
            outputs = model(**batch)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            scheduler.step()
            batch_losses.append(float(loss.item()))

        eval_metrics = evaluate(model, val_loader, device, len(label_map))
        epoch_summary = {
            "epoch": epoch,
            "loss": eval_metrics["loss"],
            "acc": eval_metrics["acc"],
            "precision": eval_metrics["precision"],
            "recall": eval_metrics["recall"],
            "f1": eval_metrics["f1"],
            "train_loss": float(np.mean(batch_losses)) if batch_losses else 0.0,
        }
        metric_history.append(epoch_summary)
        print(json.dumps({"job_id": args.job_id, "type": "metric", **epoch_summary}), flush=True)

        if epoch_summary["f1"] > best_f1:
            best_f1 = epoch_summary["f1"]
            best_epoch_summary = epoch_summary
            model.save_pretrained(artifact_dir)
            tokenizer.save_pretrained(artifact_dir)
            (artifact_dir / "metadata.json").write_text(
                json.dumps(
                    {
                        "job_id": args.job_id,
                        "base_model": args.base_model,
                        "label_map": label_map,
                        "prompt_text": args.prompt_text,
                        "max_length": args.max_length,
                        "seed": args.seed,
                        "device": device,
                        "train_counts": train_counts,
                        "val_counts": val_counts,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

    metrics_path = args.out_dir / f"{args.job_id}_metrics.json"
    metrics_path.write_text(
        json.dumps(
            {
                "job_id": args.job_id,
                "metrics": metric_history,
                "best": best_epoch_summary,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    dataset_class_counts: dict[str, int] = {}
    for row in dataset_rows:
        label_name = str(row["label_name"])
        dataset_class_counts[label_name] = dataset_class_counts.get(label_name, 0) + 1

    summary = {
        "job_id": args.job_id,
        "artifact": str(artifact_dir),
        "best": best_epoch_summary,
        "prompt_text": args.prompt_text,
        "fewshot_size": args.fewshot_size,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "base_model": args.base_model,
        "max_length": args.max_length,
        "seed": args.seed,
        "device": device,
        "dataset": {
            "path": str(args.dataset_path),
            "total": len(dataset_rows),
            "train": len(train_rows),
            "val": len(val_rows),
            "classes": dataset_class_counts,
            "trainClasses": train_counts,
            "valClasses": val_counts,
        },
    }
    print(json.dumps({"type": "summary", **summary}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
