"""
一个极简的“小样本提示调优训练” Demo 脚本，用于演示
注意：当前脚本不依赖真实深度学习框架，只是生成一些虚拟的 loss / acc / f1，
方便你后续将其替换为真正的 CodeBERT / CodeT5 提示调优训练代码。
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--job_id", required=True)
    p.add_argument("--prompt_text", help="硬提示模板内容，可选")
    p.add_argument("--fewshot_size", type=int, default=32)
    p.add_argument("--epochs", type=int, default=10)
    p.add_argument("--batch_size", type=int, default=8)
    p.add_argument("--learning_rate", type=float, default=5e-5)
    p.add_argument(
        "--dataset_path",
        type=Path,
        help="JSONL 数据集路径，每行一个样本：{id, source, label(0/1)}",
    )
    p.add_argument(
        "--out_dir",
        type=Path,
        default=Path("python_scripts/demo_outputs"),
        help="用于保存训练指标和模型产物的目录",
    )
    return p.parse_args()

def load_jsonl_dataset(path: Path) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data.append(json.loads(line))
    return data


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    random.seed(42)

    dataset_info: dict[str, Any] = {"path": None, "total": None, "sampled": None, "pos": None, "neg": None}
    if args.dataset_path is not None:
        ds = load_jsonl_dataset(args.dataset_path)
        total = len(ds)
        few = min(max(1, args.fewshot_size), total) if total > 0 else 0
        sampled = random.sample(ds, few) if few > 0 else []
        pos = sum(1 for x in sampled if int(x.get("label", 0)) == 1)
        neg = sum(1 for x in sampled if int(x.get("label", 0)) == 0)
        dataset_info = {"path": str(args.dataset_path), "total": total, "sampled": few, "pos": pos, "neg": neg}

    metrics = []
    for epoch in range(1, args.epochs + 1):
        # 这里用一个简单的曲线模拟 loss/acc/f1 的变化
        loss = 1.0 / epoch * (0.5 + random.random() * 0.5)
        acc = 0.5 + 0.5 * (epoch / args.epochs) + (random.random() - 0.5) * 0.05
        acc = max(0.0, min(1.0, acc))
        f1 = acc - 0.02 + (random.random() - 0.5) * 0.05
        f1 = max(0.0, min(1.0, f1))

        m: Dict[str, Any] = {
            "epoch": epoch,
            "loss": loss,
            "acc": acc,
            "f1": f1,
        }
        metrics.append(m)

        # 也可以在这里打印日志，供 Go 后端解析 stdout
        print(json.dumps({"job_id": args.job_id, "type": "metric", **m}), flush=True)

    # 选取最优指标
    best = min(metrics, key=lambda x: x["loss"])

    # 保存指标到 json 文件（Go 后端可以读取此文件）
    metrics_path = args.out_dir / f"{args.job_id}_metrics.json"
    metrics_path.write_text(json.dumps({"job_id": args.job_id, "metrics": metrics, "best": best}, indent=2), encoding="utf-8")

    # 保存一个“模型产物”占位文件
    model_path = args.out_dir / f"{args.job_id}_model.bin"
    model_path.write_bytes(b"\x00" * 16)

    # 最终在 stdout 上输出一个汇总，便于后端一次性解析
    summary = {
        "job_id": args.job_id,
        "artifact": str(model_path),
        "best": best,
        "prompt_text": args.prompt_text,
        "fewshot_size": args.fewshot_size,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "dataset": dataset_info,
    }
    print(json.dumps({"type": "summary", **summary}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

