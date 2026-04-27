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
POSITIVE_LABEL = "vulnerable"
NEGATIVE_LABEL = "non_vulnerable"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job_id", required=True)
    parser.add_argument("--prompt_text", help="硬提示模板内容，可选")
    parser.add_argument("--fewshot_size", type=int, default=32)
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch_size", type=int, default=8)
    parser.add_argument("--learning_rate", type=float, default=2e-5)
    parser.add_argument("--base_model", default="microsoft/codebert-base")
    parser.add_argument("--max_length", type=int, default=256)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--val_ratio", type=float, default=0.2)
    parser.add_argument("--target_vuln_type", default="reentrancy")
    parser.add_argument(
        "--dataset_path",
        type=Path,
        help="支持 JSONL 文件或 smartbugs-curated 目录，建议放在 python_scripts/datasets 下",
    )
    parser.add_argument(
        "--out_dir",
        type=Path,
        default=Path("python_scripts/demo_outputs"),
        help="用于保存训练指标和模型产物的目录",
    )
    return parser.parse_args()


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def normalize_vuln_type(label_name: str) -> str:
    return label_name.strip().lower().replace(" ", "_").replace("-", "_")


def load_jsonl_dataset(path: Path) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
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
            if label_name is None:
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


def prepare_binary_dataset(rows: list[dict[str, Any]], target_vuln_type: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    target = normalize_vuln_type(target_vuln_type)
    binary_rows: list[dict[str, Any]] = []
    class_counts = {POSITIVE_LABEL: 0, NEGATIVE_LABEL: 0}

    for row in rows:
        original_label = normalize_vuln_type(str(row["label_name"]))
        label_name = POSITIVE_LABEL if original_label == target else NEGATIVE_LABEL
        class_counts[label_name] += 1
        binary_rows.append(
            {
                **row,
                "original_label_name": original_label,
                "label_name": label_name,
                "target_vuln_type": target,
            }
        )

    if class_counts[POSITIVE_LABEL] == 0:
        raise ValueError(f"target vulnerability has no samples: {target}")
    if class_counts[NEGATIVE_LABEL] == 0:
        raise ValueError("binary dataset has no negative samples")

    return binary_rows, class_counts


def split_dataset(
    rows: list[dict[str, Any]],
    fewshot_size: int,
    val_ratio: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int], dict[str, int]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        buckets.setdefault(str(row["label_name"]), []).append(row)

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


def build_label_mapping() -> dict[str, int]:
    return {NEGATIVE_LABEL: 0, POSITIVE_LABEL: 1}


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


def load_base_model(base_model: str, label_map: dict[str, int]) -> tuple[Any, Any]:
    try:
        tokenizer = AutoTokenizer.from_pretrained(base_model, local_files_only=True)
        model = AutoModelForSequenceClassification.from_pretrained(
            base_model,
            num_labels=len(label_map),
            id2label={index: label for label, index in label_map.items()},
            label2id=label_map,
            local_files_only=True,
        )
        return tokenizer, model
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            f"failed to load base model '{base_model}' from local cache; "
            "please ensure the model is downloaded before offline training"
        ) from exc


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def compute_metrics(y_true: list[int], y_pred: list[int], positive_label: int) -> dict[str, float]:
    correct = sum(1 for truth, pred in zip(y_true, y_pred) if truth == pred)
    acc = safe_div(correct, len(y_true))

    tp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == positive_label and pred == positive_label)
    fp = sum(1 for truth, pred in zip(y_true, y_pred) if truth != positive_label and pred == positive_label)
    fn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == positive_label and pred != positive_label)

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "acc": acc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
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


def evaluate(model: nn.Module, loader: DataLoader[dict[str, torch.Tensor]], device: str, positive_label: int) -> dict[str, float]:
    model.eval()
    losses: list[float] = []
    y_true: list[int] = []
    y_pred: list[int] = []
    with torch.no_grad():
        for batch in loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            outputs = model(**batch)
            losses.append(float(outputs.loss.item()))
            preds = torch.argmax(outputs.logits, dim=-1)
            y_true.extend(batch["labels"].cpu().tolist())
            y_pred.extend(preds.cpu().tolist())
    metrics = compute_metrics(y_true, y_pred, positive_label)
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

    target_vuln_type = normalize_vuln_type(args.target_vuln_type)
    binary_rows, class_counts = prepare_binary_dataset(dataset_rows, target_vuln_type)
    label_map = build_label_mapping()
    train_rows, val_rows, train_counts, val_counts = split_dataset(binary_rows, args.fewshot_size, args.val_ratio)
    if not train_rows:
        raise ValueError("training split is empty")
    if not val_rows:
        val_rows = train_rows

    tokenizer, model = load_base_model(args.base_model, label_map)

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
    positive_label_id = label_map[POSITIVE_LABEL]
    for epoch in range(1, args.epochs + 1):
        model.train()
        batch_losses: list[float] = []
        for batch in train_loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            optimizer.zero_grad()
            outputs = model(**batch)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            scheduler.step()
            batch_losses.append(float(loss.item()))

        eval_metrics = evaluate(model, val_loader, device, positive_label_id)
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
                        "target_vuln_type": target_vuln_type,
                        "negative_strategy": "one-vs-rest",
                        "raw_class_counts": class_counts,
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
        "target_vuln_type": target_vuln_type,
        "dataset": {
            "path": str(args.dataset_path),
            "total": len(binary_rows),
            "positiveTotal": class_counts[POSITIVE_LABEL],
            "negativeTotal": class_counts[NEGATIVE_LABEL],
            "train": len(train_rows),
            "val": len(val_rows),
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
