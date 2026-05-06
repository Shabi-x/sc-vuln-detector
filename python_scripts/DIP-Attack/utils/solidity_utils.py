"""
Solidity source-code analysis utilities.

Provides tokenization, syntax checking, scope analysis, and code
manipulation helpers shared by the attack and data modules.
"""

import re
from typing import List, Tuple


# ── Tokenization ──────────────────────────────────────────────────────

def tokenize_sol(code: str) -> List[str]:
    """Tokenize Solidity source into a flat list of lexemes."""
    return re.findall(
        r'[a-zA-Z_]\w*|[{}()\[\];,.]|[+\-*/=<>!&|^~%]+|\d+', code
    )


def count_tokens(code: str) -> int:
    return len(tokenize_sol(code))


# ── Syntax checking ──────────────────────────────────────────────────

def basic_syntax_check(code: str) -> bool:
    """Fast brace / parenthesis balance check."""
    bc = pc = 0
    for ch in code:
        if   ch == '{': bc += 1
        elif ch == '}': bc -= 1
        elif ch == '(': pc += 1
        elif ch == ')': pc -= 1
        if bc < 0 or pc < 0:
            return False
    return bc == 0 and pc == 0


# ── Line-level manipulation ──────────────────────────────────────────

def insert_at_line(code: str, line_idx: int, text: str) -> str:
    """Insert *text* before line *line_idx* (0-based)."""
    lines = code.split('\n')
    if 0 <= line_idx <= len(lines):
        lines.insert(line_idx, text)
    return '\n'.join(lines)


# ── Function / scope analysis ────────────────────────────────────────

def get_function_bodies(code: str) -> List[Tuple[int, int]]:
    """Return (start_line, end_line) pairs for every function body."""
    lines = code.split('\n')
    bodies: List[Tuple[int, int]] = []
    depth = 0; func_start = -1; in_func = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r'^\s*(function|constructor|fallback|receive)\s', line) or \
           re.match(r'^\s*(function|constructor|fallback|receive)\s', stripped):
            in_func = True; func_start = i
        for ch in stripped:
            if   ch == '{': depth += 1
            elif ch == '}': depth -= 1
        if in_func and depth == 0 and func_start >= 0:
            bodies.append((func_start, i))
            in_func = False; func_start = -1
    return bodies


def get_function_lines(code: str) -> List[int]:
    """Return line indices of meaningful statements inside function bodies."""
    lines = code.split('\n'); result: List[int] = []
    for start, end in get_function_bodies(code):
        for i in range(start + 1, end):
            s = lines[i].strip()
            if s and s not in ('{', '}', '') and not s.startswith('//'):
                result.append(i)
    return result


def get_insertable_positions(code: str) -> List[int]:
    """Return line indices where a new statement can be safely inserted."""
    lines = code.split('\n'); positions = set()
    for start, end in get_function_bodies(code):
        for i in range(start + 1, end):
            s = lines[i].strip()
            if s and s.endswith(';') and not s.startswith('//'):
                positions.add(i)
                if i + 1 <= end:
                    positions.add(i + 1)
    return list(positions)


# ── Variable discovery ───────────────────────────────────────────────

_RESERVED = frozenset({
    'msg', 'block', 'tx', 'this', 'super', 'sender', 'value',
    'timestamp', 'number', 'difficulty', 'origin', 'data',
    'true', 'false', 'ether', 'wei', 'gwei',
    'memory', 'storage', 'calldata', 'success',
})

_VAR_PATTERN = re.compile(
    r'\b(uint256|uint128|uint|int256|address|bool|bytes32)'
    r'\s+(?:public\s+|private\s+|internal\s+)?(\w+)'
)


def find_user_defined_vars(code: str) -> List[Tuple[str, str]]:
    """Return [(type, name), …] for user-defined variables."""
    return [
        (t, n) for t, n in _VAR_PATTERN.findall(code)
        if n not in _RESERVED and len(n) > 1
    ]


def find_var_scope(code: str, var_name: str) -> List[Tuple[int, int]]:
    """Find function-body scopes that reference *var_name*."""
    lines = code.split('\n'); scopes: List[Tuple[int, int]] = []
    pat = re.compile(r'\b' + re.escape(var_name) + r'\b')
    for start, end in get_function_bodies(code):
        body = '\n'.join(lines[start:end + 1])
        if pat.search(body):
            scopes.append((start, end))
    return scopes


def get_scope_nesting_depth(code: str, line_idx: int) -> int:
    """Compute brace-nesting depth at *line_idx*."""
    lines = code.split('\n'); depth = 0
    for i in range(min(line_idx, len(lines))):
        for ch in lines[i]:
            if   ch == '{': depth += 1
            elif ch == '}': depth -= 1
    return max(depth, 0)
