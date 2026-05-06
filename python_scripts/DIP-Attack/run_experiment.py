#!/usr/bin/env python3
"""
==========================================================================
DIP Attack — Full Experiment Runner
==========================================================================

Reproduces the DIP (Dead-code Insertion with Position estimation) baseline:
  • 4 victim models: AME, ConvMHSA, GPSCVul, Clear
  • 3 vulnerability types: reentrancy, timestamp, integer_overflow
  • 5 metrics: ASR, Δ_drop, Queries, R_p, CodeBLEU

Usage:
    # Full experiment (curated dataset preferred)
    python run_experiment.py

    # Quick smoke test
    python run_experiment.py --quick

    # Build curated dataset first, then run
    python run_experiment.py --build-dataset

    # Use only dappscan_filtered (skip curated)
    python run_experiment.py --no-curated
"""

import os, sys, json, random, time, argparse, warnings
from pathlib import Path
from datetime import datetime

import numpy as np
import torch

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from data.loader import load_dataset, load_contracts
from data.build_dataset import build_curated_dataset
from models.wrapper import create_and_train_models, MODEL_NAMES
from attacks.dip_attack import DIPAttacker
from evaluation.metrics import (
    compute_asr,
    compute_delta_drop,
    compute_avg_queries,
    compute_rp,
    compute_codebleu_approx,
)

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────

SEED = 42
MAX_QUERIES = 200
NEG_MULTIPLIER = 3
VULN_TYPES = ["reentrancy", "timestamp", "integer_overflow"]
SWC_MAP = {
    "reentrancy": "SWC-107",
    "timestamp": "SWC-116",
    "integer_overflow": "SWC-101",
}
DAPPSCAN_ROOT = PROJECT_ROOT.parent / "DAppSCAN"
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results"


def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


# ─────────────────────────────────────────────────────────────────────
# DAppSCAN filtering (reuse CCH pipeline if data not yet prepared)
# ─────────────────────────────────────────────────────────────────────

def ensure_dappscan_filtered():
    """
    Check if dappscan_filtered data exists.  If not, try to copy from
    CCH-Attack's data directory or run the filtering pipeline.
    """
    filtered = DATA_DIR / "dappscan_filtered"
    if filtered.exists() and any(filtered.rglob("*.sol")):
        return True

    # Try copying from CCH-Attack
    cch_data = PROJECT_ROOT.parent / "CCH-Attack" / "data" / "dappscan_filtered"
    if cch_data.exists() and any(cch_data.rglob("*.sol")):
        import shutil
        print("  Copying DAppSCAN filtered data from CCH-Attack …")
        if filtered.exists():
            shutil.rmtree(filtered)
        shutil.copytree(cch_data, filtered)
        return True

    # Try running CCH's filter
    if DAPPSCAN_ROOT.exists():
        print("  DAppSCAN source found but no filtered data.")
        print("  Please run CCH-Attack's experiment first to generate filtered data,")
        print("  or copy data/dappscan_filtered/ from CCH-Attack.")
        return False

    print("  ERROR: No DAppSCAN data found.")
    print("  Expected: ../DAppSCAN/ or ../CCH-Attack/data/dappscan_filtered/")
    return False


# ─────────────────────────────────────────────────────────────────────
# Experiment runner
# ─────────────────────────────────────────────────────────────────────

def run_experiment(vuln_type: str, models: dict, vuln_contracts: list,
                   safe_contracts: list, quick: bool = False) -> dict:
    """Run DIP attack on all models for one vulnerability type."""
    n_attack = min(15, len(vuln_contracts)) if quick else len(vuln_contracts)
    max_q = 50 if quick else MAX_QUERIES
    attack_contracts = vuln_contracts[:n_attack]

    print(f"\n  Attacking {n_attack} vulnerable contracts "
          f"(max_queries={max_q}) …")

    results = {}
    for mn in MODEL_NAMES:
        if mn not in models:
            continue
        model = models[mn]

        # Clean accuracy on attack set
        n_detected = sum(1 for c in attack_contracts if model(c) == 1)
        clean_acc = n_detected / n_attack * 100 if n_attack > 0 else 0
        print(f"\n    Model: {mn} "
              f"(clean det: {n_detected}/{n_attack} = {clean_acc:.1f}%)")

        t0 = time.time()
        attack_results = []
        done = 0

        sys.stdout.write(f"      DIP … ")
        sys.stdout.flush()

        for i, contract in enumerate(attack_contracts):
            if model(contract) != 1:
                continue  # skip samples model doesn't detect
            attacker = DIPAttacker(
                vuln_type=vuln_type,
                max_queries=max_q,
                seed=SEED + i,
            )
            res = attacker.attack(contract, model)
            attack_results.append(res)
            done += 1
            if done % 5 == 0 or done == n_detected:
                sys.stdout.write(f"[{done}/{n_detected}]")
                sys.stdout.flush()

        elapsed = time.time() - t0

        # Compute metrics
        asr_m, asr_s = compute_asr(attack_results)
        drop_m, drop_s = compute_delta_drop(clean_acc, attack_results)
        q_m, q_s = compute_avg_queries(attack_results, max_q)
        rp_m, rp_s = compute_rp(attack_results)

        originals = [
            attack_contracts[i]
            for i in range(len(attack_contracts))
            if models[mn](attack_contracts[i]) == 1
        ][:len(attack_results)]
        adversarials = [r['adv_code'] for r in attack_results]
        cb_m, cb_s = compute_codebleu_approx(originals, adversarials)

        results[mn] = {
            'ASR': {'mean': asr_m, 'std': asr_s},
            'delta_drop': {'mean': drop_m, 'std': drop_s},
            'queries': {'mean': q_m, 'std': q_s},
            'R_p': {'mean': rp_m, 'std': rp_s},
            'CodeBLEU': {'mean': cb_m, 'std': cb_s},
            'n_attacked': len(attack_results),
            'n_detected': n_detected,
            'clean_acc': clean_acc,
            'time': elapsed,
        }

        sys.stdout.write(
            f" ASR={asr_m:.1f}% Δ={drop_m:.1f}% Q={q_m:.0f} "
            f"Rp={rp_m:.3f} CB={cb_m:.3f} ({elapsed:.1f}s)\n"
        )
        sys.stdout.flush()

    return results


# ─────────────────────────────────────────────────────────────────────
# Result formatting
# ─────────────────────────────────────────────────────────────────────

def print_summary(all_results: dict):
    """Print a formatted summary table."""
    print("\n" + "=" * 80)
    print("  DIP Attack — Results Summary")
    print("=" * 80)

    header = f"{'VulnType':<18} {'Model':<10} {'ASR%':>8} {'Δ_drop':>8} " \
             f"{'Queries':>8} {'R_p':>8} {'CodeBLEU':>8} {'N':>4}"
    print(header)
    print("-" * 80)

    for vuln_type, vresults in all_results.items():
        for mn, mr in vresults.items():
            print(
                f"  {vuln_type:<16} {mn:<10} "
                f"{mr['ASR']['mean']:>7.1f} "
                f"{mr['delta_drop']['mean']:>7.1f} "
                f"{mr['queries']['mean']:>7.0f} "
                f"{mr['R_p']['mean']:>7.3f} "
                f"{mr['CodeBLEU']['mean']:>7.3f} "
                f"{mr['n_attacked']:>4}"
            )
        print("-" * 80)


def save_results(all_results: dict, output_dir: Path):
    """Save results as JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = output_dir / f"dip_results_{timestamp}.json"
    with open(out_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Results saved to {out_file}")


# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DIP Attack Experiment Runner"
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Quick mode: fewer samples, fewer queries",
    )
    parser.add_argument(
        "--build-dataset", action="store_true",
        help="Build curated dataset before running experiment",
    )
    parser.add_argument(
        "--no-curated", action="store_true",
        help="Use dappscan_filtered only (skip curated dataset)",
    )
    parser.add_argument(
        "--vuln-types", nargs="+", default=VULN_TYPES,
        choices=VULN_TYPES,
        help="Vulnerability types to evaluate",
    )
    parser.add_argument(
        "--max-queries", type=int, default=MAX_QUERIES,
        help="Max queries per attack (default: 200)",
    )
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    # MPS fallback for Clear model
    os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")

    set_seed(args.seed)
    max_queries = args.max_queries

    print("=" * 60)
    print("  DIP Attack — Baseline Reproduction")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Vuln types: {args.vuln_types}")
    print(f"  Max queries: {max_queries}")
    print(f"  Quick mode: {args.quick}")
    print(f"  Use curated: {not args.no_curated}")
    print("=" * 60)

    # Step 1: Ensure data exists
    if not ensure_dappscan_filtered():
        sys.exit(1)

    # Step 2: Optionally build curated dataset
    if args.build_dataset:
        print("\n  Building curated dataset …")
        build_curated_dataset(DATA_DIR, min_detect=1)

    # Step 3: Run experiments
    all_results = {}
    total_t0 = time.time()

    for vuln_type in args.vuln_types:
        print(f"\n{'='*60}")
        print(f"  Vulnerability: {vuln_type} ({SWC_MAP.get(vuln_type, '?')})")
        print(f"{'='*60}")

        # Load data
        vuln, safe = load_dataset(
            DATA_DIR, vuln_type,
            prefer_curated=(not args.no_curated),
        )
        if not vuln:
            print(f"  [SKIP] No vulnerable contracts for {vuln_type}")
            continue
        print(f"  Loaded: {len(vuln)} vuln, {len(safe)} safe")

        # Train models
        print("  Training victim models …")
        n_safe_train = min(len(safe), len(vuln) * NEG_MULTIPLIER)
        train_safe = safe[:n_safe_train]
        models = create_and_train_models(vuln_type, vuln, train_safe)

        # Run attack
        results = run_experiment(
            vuln_type, models, vuln, safe, quick=args.quick
        )
        all_results[vuln_type] = results

    total_elapsed = time.time() - total_t0

    # Step 4: Summary
    print_summary(all_results)
    print(f"\n  Total time: {total_elapsed:.1f}s")

    # Step 5: Save
    save_results(all_results, RESULTS_DIR)

    print("\n  Done!")


if __name__ == "__main__":
    main()
