"""
Build a curated high-detection-rate dataset.

For each vulnerability type, train all four victim models on the full
DAppSCAN-filtered data, then keep only the vulnerable samples that at
least one model correctly detects.  This ensures every sample in the
curated set is *attackable* — giving a meaningful ASR measurement.

Usage (standalone):
    python -m data.build_dataset [--data-root data] [--min-detect 1]

The script writes to ``data/curated/{vuln_type}/vuln/`` and
``data/curated/{vuln_type}/safe/``.
"""

import argparse, random, shutil, sys, os
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import torch

from data.loader import load_contracts
from models.wrapper import create_and_train_models, MODEL_NAMES

SEED = 42
VULN_TYPES = ["reentrancy", "timestamp", "integer_overflow"]
NEG_MULTIPLIER = 3


def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def build_curated_dataset(data_root: Path, min_detect: int = 1):
    """
    Build curated dataset for all vulnerability types.

    Parameters
    ----------
    data_root : Path
        Root data directory (contains ``dappscan_filtered/``).
    min_detect : int
        Minimum number of models that must detect a sample for it to be
        included in the curated set.
    """
    set_seed(SEED)

    for vuln_type in VULN_TYPES:
        print(f"\n{'='*60}")
        print(f"  Building curated dataset for: {vuln_type}")
        print(f"{'='*60}")

        src_dir = data_root / "dappscan_filtered" / vuln_type
        vuln_dir = src_dir / "vulnerable"
        safe_dir = src_dir / "non_vulnerable"

        if not vuln_dir.exists():
            print(f"  [SKIP] {vuln_dir} does not exist")
            continue

        vuln_contracts = load_contracts(vuln_dir)
        safe_contracts = load_contracts(safe_dir)
        print(f"  Source: {len(vuln_contracts)} vuln, {len(safe_contracts)} safe")

        if not vuln_contracts:
            print("  [SKIP] No vulnerable contracts found")
            continue

        # Train models
        print("  Training victim models …")
        n_safe_train = min(len(safe_contracts),
                           len(vuln_contracts) * NEG_MULTIPLIER)
        train_safe = safe_contracts[:n_safe_train]
        models = create_and_train_models(vuln_type, vuln_contracts, train_safe)

        # Evaluate detection on vulnerable samples
        print("  Evaluating detection rates …")
        detected_counts = []
        for i, code in enumerate(vuln_contracts):
            n_detect = sum(1 for mn in MODEL_NAMES if models[mn](code) == 1)
            detected_counts.append(n_detect)

        # Filter: keep samples detected by ≥ min_detect models
        curated_indices = [
            i for i, cnt in enumerate(detected_counts) if cnt >= min_detect
        ]
        print(f"  Detection distribution: "
              f"0={detected_counts.count(0)}, "
              f"1={detected_counts.count(1)}, "
              f"2={detected_counts.count(2)}, "
              f"3={detected_counts.count(3)}, "
              f"4={detected_counts.count(4)}")
        print(f"  Curated: {len(curated_indices)} / {len(vuln_contracts)} "
              f"(min_detect={min_detect})")

        if not curated_indices:
            print("  [WARN] No samples passed the detection filter!")
            continue

        # Write curated dataset
        out_vuln = data_root / "curated" / vuln_type / "vulnerable"
        out_safe = data_root / "curated" / vuln_type / "non_vulnerable"
        out_vuln.mkdir(parents=True, exist_ok=True)
        out_safe.mkdir(parents=True, exist_ok=True)

        # Copy curated vulnerable samples
        vuln_files = sorted((src_dir / "vulnerable").glob("*.sol"))
        for idx in curated_indices:
            if idx < len(vuln_files):
                shutil.copy2(vuln_files[idx], out_vuln / vuln_files[idx].name)
            else:
                # If files don't match 1:1, write from memory
                fname = f"curated_{idx:04d}.sol"
                (out_vuln / fname).write_text(
                    vuln_contracts[idx], encoding='utf-8'
                )

        # Copy safe samples (use same set)
        safe_files = sorted((src_dir / "non_vulnerable").glob("*.sol"))
        for sf in safe_files:
            shutil.copy2(sf, out_safe / sf.name)

        print(f"  Written to {out_vuln} ({len(curated_indices)} files)")

    print(f"\n{'='*60}")
    print("  Curated dataset build complete!")
    print(f"{'='*60}\n")


# ─────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Build curated high-detection-rate dataset"
    )
    parser.add_argument(
        "--data-root", type=Path,
        default=PROJECT_ROOT / "data",
        help="Root data directory (default: data/)",
    )
    parser.add_argument(
        "--min-detect", type=int, default=1,
        help="Min models that must detect a sample (default: 1)",
    )
    args = parser.parse_args()
    build_curated_dataset(args.data_root, args.min_detect)


if __name__ == "__main__":
    main()
