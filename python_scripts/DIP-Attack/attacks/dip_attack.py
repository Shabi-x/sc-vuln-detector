"""
DIP Attack — faithful reproduction of the three-phase pipeline:

  Phase 1  Scope-aware variable renaming
           (semantic role + scope nesting depth, NOT frequency-based)
  Phase 2  Gradient-estimated position selection
           (finite-difference on model score, NOT 5-probe sampling)
  Phase 3  Dead-code insertion
           (plain ``require(predicate)`` extracted via classify_and_transform,
            NO chaos_func wrapping)

Position ranking reuses CCH's ``compute_line_impact`` + ``classify_and_transform``
to decide WHERE and WHAT to insert.
"""

import re, random, math
from typing import Dict, List, Optional, Tuple

import numpy as np

from utils.solidity_utils import (
    tokenize_sol,
    count_tokens,
    basic_syntax_check,
    insert_at_line,
    get_function_bodies,
    get_function_lines,
    get_insertable_positions,
    find_user_defined_vars,
    find_var_scope,
    get_scope_nesting_depth,
)
from models.features import (
    structural_features,
    vuln_keyword_features,
    name_features,
)


# =====================================================================
# Helpers shared with CCH but kept local to avoid circular imports
# =====================================================================

class SimpleSemanticScorer:
    """Feature-based line-impact scorer (same logic as CCH)."""

    def __init__(self, vuln_type: str):
        self.vuln_type = vuln_type

    def _feat(self, code: str) -> np.ndarray:
        return np.concatenate([
            structural_features(code),
            vuln_keyword_features(code, self.vuln_type),
            name_features(code),
        ])

    def compute_line_impact(self, code: str, line_idx: int) -> float:
        """Cosine-distance impact when *line_idx* is removed."""
        lines = code.split('\n')
        if line_idx < 0 or line_idx >= len(lines):
            return 0.0
        orig = self._feat(code)
        mod_lines = lines.copy()
        mod_lines[line_idx] = ""
        mod = self._feat('\n'.join(mod_lines))
        d = np.dot(orig, mod)
        n1, n2 = np.linalg.norm(orig), np.linalg.norm(mod)
        if n1 == 0 or n2 == 0:
            return 0.0
        return float(1.0 - d / (n1 * n2))


def classify_and_transform(line: str) -> Optional[str]:
    """
    Extract a tautological predicate from a Solidity statement.

    Returns a string suitable for ``require(<predicate>);`` or *None*.
    Identical to CCH's implementation.
    """
    stripped = line.strip().rstrip(';')
    if not stripped or stripped.startswith('//') or stripped in ('{', '}', ''):
        return None
    # Assignment → (rhs == rhs)
    m = re.match(r'^\s*(?:\w+\s+)*(\w+)\s*=\s*(.+)', stripped)
    if m and 'mapping' not in stripped and '{' not in stripped:
        rhs = m.group(2).strip()
        if rhs and rhs not in ('', '{', '}'):
            return f"({rhs} == {rhs})"
    # Conditional / require / assert → extract condition
    m = re.match(r'^\s*(?:if|require|assert)\s*\((.+)\)\s*', stripped)
    if m:
        cond = m.group(1)
        if cond and '(' not in cond.replace('(', '', 1):
            return f"({cond})"
        return "true"
    # Function call → true
    if re.match(r'^\s*\w+[\.\w]*\s*\(', stripped):
        return "true"
    return None


# =====================================================================
# Semantic-role rename scoring (DIP original logic)
# =====================================================================

_ROLE_KEYWORDS: Dict[str, List[str]] = {
    "balance":   ["balance", "bal", "amount", "amt", "value", "val", "fund"],
    "address":   ["addr", "address", "sender", "receiver", "owner", "to", "from"],
    "control":   ["flag", "ok", "status", "state", "lock", "guard", "paused"],
    "counter":   ["count", "cnt", "num", "index", "idx", "len", "length", "total"],
    "hash":      ["hash", "digest", "keccak", "sha"],
    "time":      ["time", "timestamp", "ts", "deadline", "expiry", "block"],
    "temp":      ["tmp", "temp", "aux", "scratch", "result", "ret"],
}


def _semantic_role(var_name: str) -> str:
    """Classify a variable name into a semantic role category."""
    lower = var_name.lower()
    for role, keywords in _ROLE_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return role
    return "generic"


def _rename_score(code: str, var_name: str, var_type: str) -> float:
    """
    DIP rename priority: semantic_role_weight × scope_nesting_depth.

    Variables with security-relevant roles (balance, address) and deeper
    nesting are renamed first because they contribute more to model features.
    """
    role = _semantic_role(var_name)
    role_weight = {
        "balance": 1.0, "address": 0.9, "control": 0.8,
        "hash": 0.7, "time": 0.7, "counter": 0.5,
        "temp": 0.3, "generic": 0.4,
    }.get(role, 0.4)

    # Find first occurrence line to compute nesting depth
    lines = code.split('\n')
    depth = 1
    pat = re.compile(r'\b' + re.escape(var_name) + r'\b')
    for i, ln in enumerate(lines):
        if pat.search(ln):
            depth = max(get_scope_nesting_depth(code, i), 1)
            break

    return role_weight * depth


def _generate_semantic_name(role: str, rng: random.Random) -> str:
    """Generate a neutral replacement name based on semantic role."""
    prefixes = {
        "balance": ["_val", "_v", "_n"],
        "address": ["_a", "_ref", "_p"],
        "control": ["_f", "_s", "_c"],
        "counter": ["_i", "_k", "_j"],
        "hash":    ["_h", "_d", "_x"],
        "time":    ["_t", "_ts", "_w"],
        "temp":    ["_r", "_m", "_q"],
        "generic": ["_u", "_z", "_e"],
    }
    prefix = rng.choice(prefixes.get(role, ["_u"]))
    return f"{prefix}{rng.randint(100, 99999)}"


# =====================================================================
# DIP Attacker
# =====================================================================

class DIPAttacker:
    """
    Three-phase DIP attack:

    1. **Scope-aware rename** — prioritised by semantic role × nesting depth
    2. **Gradient-estimated position** — finite-difference on model score
       using CCH's ``compute_line_impact`` for initial ranking, then
       model-score probing for fine-grained ordering
    3. **Dead-code insertion** — plain ``require(predicate)`` statements
       where predicates come from ``classify_and_transform``
    """

    MAX_RENAME = 5          # rename up to 5 variables
    PROBE_BUDGET_FRAC = 0.3 # spend ≤30% of query budget on position probing
    FD_EPSILON = 1e-4       # finite-difference step (conceptual)

    def __init__(self, vuln_type: str, max_queries: int = 200,
                 seed: int = 42):
        self.vuln_type = vuln_type
        self.max_queries = max_queries
        self.rng = random.Random(seed)
        self.scorer = SimpleSemanticScorer(vuln_type)

    # ── Phase 1: scope-aware rename ──────────────────────────────────

    def _scope_aware_rename(self, code: str, var_name: str,
                            new_name: str,
                            scopes: List[Tuple[int, int]]) -> str:
        lines = code.split('\n')
        pat = re.compile(r'\b' + re.escape(var_name) + r'\b')
        for start, end in scopes:
            for i in range(start, min(end + 1, len(lines))):
                lines[i] = pat.sub(new_name, lines[i])
        return '\n'.join(lines)

    def _rename_phase(self, code: str) -> str:
        vf = find_user_defined_vars(code)
        if not vf:
            return code
        # Score by semantic role × nesting depth (DIP original logic)
        scored = [
            (t, n, _rename_score(code, n, t)) for t, n in vf
        ]
        scored.sort(key=lambda x: x[2], reverse=True)

        result = code
        renamed: set = set()
        for _, old, _ in scored:
            if old in renamed:
                continue
            scopes = find_var_scope(result, old)
            if not scopes:
                continue
            role = _semantic_role(old)
            new = _generate_semantic_name(role, self.rng)
            nr = self._scope_aware_rename(result, old, new, scopes)
            if nr != result and basic_syntax_check(nr):
                result = nr
                renamed.add(old)
            if len(renamed) >= self.MAX_RENAME:
                break
        return result

    # ── Phase 2: gradient-estimated position selection ────────────────

    def _rank_positions_by_impact(self, code: str) -> List[int]:
        """
        Initial ranking via CCH's feature-based ``compute_line_impact``.
        This is cheap (no model queries) and gives a good starting order.
        """
        positions = get_insertable_positions(code)
        if not positions:
            return []
        scored = [
            (p, self.scorer.compute_line_impact(code, p))
            for p in positions
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [p for p, _ in scored]

    def _finite_difference_rerank(self, code: str, positions: List[int],
                                  model, budget: int) -> Tuple[List[int], int]:
        """
        Finite-difference gradient estimation on model score.

        For each probed position, insert a neutral probe statement and
        measure Δscore.  Positions with the largest score *drop* are
        ranked first.

        Returns (reranked_positions, queries_used).
        """
        if not positions or budget <= 1:
            return positions, 0
        if not hasattr(model, 'predict_score'):
            self.rng.shuffle(positions)
            return positions, 0

        queries = 0
        base_score = model.predict_score(code)
        queries += 1

        n_probe = min(len(positions), budget - 1)
        probe_positions = positions[:n_probe]

        impacts: List[Tuple[int, float]] = []
        for pos in probe_positions:
            probe_code = insert_at_line(code, pos, "        uint256 _probe = 0;")
            if not basic_syntax_check(probe_code):
                impacts.append((pos, 0.0))
                continue
            probe_score = model.predict_score(probe_code)
            queries += 1
            # Finite-difference: Δ = base - probe (larger = better position)
            delta = base_score - probe_score
            impacts.append((pos, delta))

        # Sort by impact descending
        impacts.sort(key=lambda x: x[1], reverse=True)
        ranked = [p for p, _ in impacts]

        # Append unprobed positions in impact-ranked order (from feature scorer)
        probed_set = set(ranked)
        remaining = [p for p in positions if p not in probed_set]
        return ranked + remaining, queries

    # ── Phase 3: dead-code insertion (require(predicate)) ────────────

    def _collect_predicates(self, code: str) -> List[str]:
        """
        Extract tautological predicates from the code itself using
        ``classify_and_transform`` (CCH's approach).
        """
        predicates: List[str] = []
        for line in code.split('\n'):
            p = classify_and_transform(line)
            if p and p != "true":
                predicates.append(p)
            if len(predicates) >= 30:
                break
        # Always include some fallback predicates
        fallbacks = [
            "true",
            "(1 == 1)",
            "(msg.sender == msg.sender)",
            "(block.number > 0)",
            "(gasleft() > 0)",
            "(address(this) != address(0))",
        ]
        predicates.extend(fallbacks)
        return predicates

    def _gen_require_stmt(self, predicate: str) -> str:
        """Generate a plain require statement (no chaos_func)."""
        return f"        require({predicate});"

    # ── Main attack loop ─────────────────────────────────────────────

    def attack(self, code: str, model) -> Dict:
        queries = 0
        orig_tok = count_tokens(code)

        # ── Phase 1: scope-aware rename ──────────────────────────────
        cur = self._rename_phase(code)
        queries += 1
        if model(cur) == 0:
            return self._success(cur, queries, orig_tok)

        # ── Phase 2: position ranking ────────────────────────────────
        # Step 2a: cheap feature-based ranking (no queries)
        ranked_pos = self._rank_positions_by_impact(cur)
        if not ranked_pos:
            return self._fail(code, queries, orig_tok)

        # Step 2b: finite-difference reranking (uses queries)
        probe_budget = max(
            3, int(self.max_queries * self.PROBE_BUDGET_FRAC)
        )
        probe_budget = min(probe_budget, self.max_queries - queries)
        ranked_pos, q_used = self._finite_difference_rerank(
            cur, ranked_pos, model, probe_budget
        )
        queries += q_used

        # ── Phase 3: dead-code insertion ─────────────────────────────
        predicates = self._collect_predicates(cur)
        self.rng.shuffle(predicates)

        pos_idx = 0
        n_inserted = 0
        n_syntax_fail = 0
        cur_score = (
            model.predict_score(cur) if hasattr(model, 'predict_score')
            else 1.0
        )
        queries += 1

        while queries < self.max_queries:
            if not ranked_pos:
                break
            # Safety: break after too many consecutive syntax failures
            if n_syntax_fail > len(ranked_pos) * 3:
                break

            p = ranked_pos[pos_idx % len(ranked_pos)]
            pos_idx += 1

            # Pick a predicate (cycle through)
            pred = predicates[n_inserted % len(predicates)]
            stmt = self._gen_require_stmt(pred)
            cand = insert_at_line(cur, p, stmt)

            if not basic_syntax_check(cand):
                n_syntax_fail += 1
                continue
            n_syntax_fail = 0

            queries += 1
            if hasattr(model, 'predict_score'):
                new_score = model.predict_score(cand)
                if new_score < 0.5:
                    return self._success(cand, queries, orig_tok)
                # Greedy accept if improved, or with exploration probability
                if new_score <= cur_score or self.rng.random() < 0.5:
                    cur = cand
                    cur_score = new_score
                    n_inserted += 1
            else:
                if model(cand) == 0:
                    return self._success(cand, queries, orig_tok)
                cur = cand
                n_inserted += 1

            # Re-rank positions every 10 insertions (positions shift after inserts)
            if n_inserted > 0 and n_inserted % 10 == 0:
                ranked_pos = get_insertable_positions(cur)
                self.rng.shuffle(ranked_pos)
                pos_idx = 0

        return self._fail(cur, queries, orig_tok)

    # ── Result helpers ───────────────────────────────────────────────

    def _success(self, adv_code: str, queries: int, orig_tok: int) -> Dict:
        return {
            'success': True,
            'adv_code': adv_code,
            'queries': queries,
            'perturbation_tokens': abs(count_tokens(adv_code) - orig_tok),
            'original_tokens': orig_tok,
        }

    def _fail(self, code: str, queries: int, orig_tok: int) -> Dict:
        return {
            'success': False,
            'adv_code': code,
            'queries': queries,
            'perturbation_tokens': abs(count_tokens(code) - orig_tok),
            'original_tokens': orig_tok,
        }
