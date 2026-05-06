"""
Five evaluation metrics for adversarial attack experiments:

  ASR          Attack Success Rate (%)
  Δ_drop       Clean accuracy − adversarial accuracy (pp)
  Queries      Average queries for successful attacks
  R_p          Perturbation rate (added tokens / original tokens)
  CodeBLEU     Approximate CodeBLEU (n-gram BLEU + Jaccard)
"""

import math
from collections import Counter
from typing import List, Dict, Tuple

import numpy as np

from utils.solidity_utils import tokenize_sol


# ─────────────────────────────────────────────────────────────────────
# ASR
# ─────────────────────────────────────────────────────────────────────

def compute_asr(results: List[Dict]) -> Tuple[float, float]:
    """Return (mean%, std%) of attack success rate."""
    if not results:
        return 0.0, 0.0
    s = [1.0 if r['success'] else 0.0 for r in results]
    mean = float(np.mean(s) * 100)
    std = float(np.std(s) * 100 / max(np.sqrt(len(s)), 1))
    return mean, std


# ─────────────────────────────────────────────────────────────────────
# Δ_drop
# ─────────────────────────────────────────────────────────────────────

def compute_delta_drop(clean_acc: float,
                       results: List[Dict]) -> Tuple[float, float]:
    """Return (drop_pp, std_pp)."""
    if not results:
        return 0.0, 0.0
    n = len(results)
    succ = sum(1 for r in results if r['success'])
    adv_acc = (1.0 - succ / n) * 100
    drop = clean_acc - adv_acc
    s = [1.0 if r['success'] else 0.0 for r in results]
    std = float(np.std(s) * 100 / max(np.sqrt(n), 1))
    return float(drop), std


# ─────────────────────────────────────────────────────────────────────
# Average queries
# ─────────────────────────────────────────────────────────────────────

def compute_avg_queries(results: List[Dict],
                        max_queries: int = 200) -> Tuple[float, float]:
    """Average queries for *successful* attacks; fallback to all if none."""
    succ = [r['queries'] for r in results if r['success']]
    if not succ:
        all_q = [r['queries'] for r in results]
        return (float(np.mean(all_q)) if all_q else float(max_queries)), 0.0
    return float(np.mean(succ)), float(np.std(succ) / max(np.sqrt(len(succ)), 1))


# ─────────────────────────────────────────────────────────────────────
# R_p  (perturbation rate)
# ─────────────────────────────────────────────────────────────────────

def compute_rp(results: List[Dict]) -> Tuple[float, float]:
    """Perturbation rate = added_tokens / original_tokens (successful only)."""
    succ = [r for r in results if r['success'] and r['original_tokens'] > 0]
    if not succ:
        return 0.0, 0.0
    rates = [r['perturbation_tokens'] / r['original_tokens'] for r in succ]
    return float(np.mean(rates)), float(np.std(rates) / max(np.sqrt(len(rates)), 1))


# ─────────────────────────────────────────────────────────────────────
# Approximate CodeBLEU
# ─────────────────────────────────────────────────────────────────────

def _ngram_overlap(ref_tokens: List[str], hyp_tokens: List[str],
                   n: int) -> float:
    ref_ng = Counter(tuple(ref_tokens[i:i + n])
                     for i in range(len(ref_tokens) - n + 1))
    hyp_ng = Counter(tuple(hyp_tokens[i:i + n])
                     for i in range(len(hyp_tokens) - n + 1))
    overlap = sum((ref_ng & hyp_ng).values())
    total = sum(hyp_ng.values())
    return overlap / total if total > 0 else 0.0


def compute_codebleu_approx(originals: List[str],
                            adversarials: List[str]) -> Tuple[float, float]:
    """
    Lightweight CodeBLEU approximation:
      0.5 × 4-gram BLEU  +  0.5 × token-set Jaccard
    """
    scores: List[float] = []
    for orig, adv in zip(originals, adversarials):
        if orig == adv:
            scores.append(1.0)
            continue
        to = tokenize_sol(orig)
        ta = tokenize_sol(adv)
        if not to or not ta:
            scores.append(0.0)
            continue
        # n-gram BLEU (1..4)
        bleu_scores = [_ngram_overlap(to, ta, n) for n in range(1, 5)]
        if all(s > 0 for s in bleu_scores):
            bleu = math.exp(
                sum(math.log(max(s, 1e-10)) for s in bleu_scores) / 4
            )
        else:
            bleu = 0.0
        # Token-set Jaccard
        so, sa = set(to), set(ta)
        jac = len(so & sa) / len(so | sa) if (so | sa) else 0.0
        scores.append(0.5 * bleu + 0.5 * jac)

    if not scores:
        return 0.0, 0.0
    return (
        float(np.mean(scores)),
        float(np.std(scores) / max(np.sqrt(len(scores)), 1)),
    )
