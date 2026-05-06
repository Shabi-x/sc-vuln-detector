"""
Feature extraction for victim models.

Three feature families:
  1. Structural features   (10-dim)  — line counts, brace depth, etc.
  2. Vulnerability keywords (15-dim) — per-vuln-type keyword frequencies
  3. Name features          (32-dim) — hashed identifier fingerprint
  4. Call-graph features    (32-dim) — function calls, state variables, etc.
  5. Expert pattern features (3-dim) — hand-crafted vulnerability patterns
"""

import re, hashlib
from collections import Counter
from typing import List

import numpy as np


# ── Vulnerability keyword dictionaries ────────────────────────────────

VULN_KEYWORDS = {
    "reentrancy": [
        ".call{", ".call.value(", ".send(", "msg.sender.call", "payable(",
        "delegatecall", "balance", "withdraw", "external", "fallback",
        "receive", "gasleft", "msg.value", "transfer(", "success",
    ],
    "timestamp": [
        "block.timestamp", "now", "block.difficulty", "block.number",
        "keccak256", "random", "seed", "winner", "lottery",
        "abi.encodePacked", "deadline", "participants", "modulo",
        "block.coinbase", "blockhash",
    ],
    "integer_overflow": [
        "unchecked", "overflow", "underflow", "SafeMath", "uint8",
        "uint16", "uint128", "int8", "totalSupply", "mint", "burn",
        "rewardRate", "safeAdd", "safeSub", "safeMul",
    ],
}


# ── Feature extractors ───────────────────────────────────────────────

def structural_features(code: str) -> np.ndarray:
    """10-dim structural feature vector."""
    lines = code.split('\n')
    f = np.zeros(10, dtype=np.float32)
    words = re.findall(r'\b\w+\b', code)
    wc = Counter(words)
    f[0] = len(lines) / 200.
    f[1] = wc.get('function', 0) / 20.
    f[2] = code.count('{') / 40.
    f[3] = code.count('(') / 40.
    f[4] = wc.get('require', 0) / 10.
    f[5] = wc.get('emit', 0) / 10.
    f[6] = wc.get('mapping', 0) / 10.
    f[7] = code.count('//') / 20.
    f[8] = len(code) / 5000.
    f[9] = code.count(';') / 40.
    return f


def vuln_keyword_features(code: str, vuln_type: str) -> np.ndarray:
    """15-dim keyword frequency vector for a specific vulnerability type."""
    kws = VULN_KEYWORDS.get(vuln_type, [])
    f = np.zeros(15, dtype=np.float32)
    for i, kw in enumerate(kws[:15]):
        f[i] = min(code.count(kw), 10) / 10.0
    return f


def name_features(code: str) -> np.ndarray:
    """32-dim hashed identifier fingerprint."""
    f = np.zeros(32, dtype=np.float32)
    idents = re.findall(r'\b([a-zA-Z_]\w{2,})\b', code)
    for ident in idents[:64]:
        h = int(hashlib.md5(ident.encode()).hexdigest()[:8], 16)
        f[h % 32] += 1.0
    s = f.sum()
    if s > 0:
        f /= s
    return f


def build_call_graph_features(code: str) -> np.ndarray:
    """32-dim call-graph feature vector (AME / GPSCVul graph proxy)."""
    f = np.zeros(32, dtype=np.float32)
    words = re.findall(r'\b\w+\b', code)
    wc = Counter(words)
    func_defs = re.findall(r'\bfunction\s+(\w+)', code)
    f[0] = len(func_defs) / 20.
    ic = sum(max(wc.get(fn, 0) - 1, 0) for fn in func_defs)
    f[1] = ic / 20.
    f[2] = code.count('.(') / 30.
    f[3] = (wc.get('mapping', 0) + wc.get('uint256', 0) + wc.get('address', 0)
            + wc.get('bool', 0) + wc.get('bytes32', 0)) / 15.
    f[4] = wc.get('modifier', 0) / 5.
    f[5] = wc.get('event', 0) / 10.
    f[6] = wc.get('is', 0) / 5.
    f[7] = wc.get('require', 0) / 10.
    f[8] = wc.get('assert', 0) / 5.
    f[9] = wc.get('for', 0) / 5.
    f[10] = wc.get('while', 0) / 5.
    f[11] = wc.get('if', 0) / 10.
    f[12] = wc.get('else', 0) / 10.
    md, d = 0, 0
    for ch in code:
        if ch == '{':
            d += 1; md = max(md, d)
        elif ch == '}':
            d -= 1
    f[13] = md / 10.
    f[14] = code.count('=') / 30.
    f[15] = wc.get('public', 0) / 10.
    f[16] = wc.get('private', 0) / 10.
    f[17] = wc.get('internal', 0) / 10.
    f[18] = wc.get('external', 0) / 10.
    f[19] = wc.get('payable', 0) / 5.
    f[20] = wc.get('view', 0) / 10.
    f[21] = wc.get('pure', 0) / 10.
    f[22] = wc.get('storage', 0) / 10.
    f[23] = wc.get('memory', 0) / 10.
    f[24] = wc.get('return', 0) / 10.
    f[25] = wc.get('contract', 0) / 5.
    f[26] = wc.get('library', 0) / 3.
    f[27] = wc.get('interface', 0) / 3.
    has_call = '.call{' in code or '.call.value(' in code or '.send(' in code
    f[28] = 1.0 if has_call else 0.0
    f[29] = wc.get('delegatecall', 0) / 3.
    f[30] = wc.get('selfdestruct', 0) / 3.
    f[31] = wc.get('assembly', 0) / 5.
    return f


def expert_pattern_features(code: str, vuln_type: str) -> np.ndarray:
    """3-dim expert pattern scores (AME pattern_extractor style)."""
    p = np.zeros(3, dtype=np.float32)
    if vuln_type == "reentrancy":
        p[0] = 1.0 if re.search(r'\.call\{|\.call\.value|\.send\(|\.transfer\(', code) else 0.0
        p[1] = 1.0 if re.search(r'\.call\{.*?;.*?\w+\s*[-+]?=', code, re.DOTALL) else 0.0
        p[2] = 0.0 if re.search(r'nonReentrant|ReentrancyGuard|locked\s*=\s*true', code) else 1.0
    elif vuln_type == "timestamp":
        p[0] = 1.0 if re.search(r'block\.timestamp|now', code) else 0.0
        p[1] = 1.0 if re.search(r'block\.timestamp.*?%|keccak256.*?block\.timestamp', code, re.DOTALL) else 0.0
        p[2] = 1.0 if re.search(r'block\.difficulty|blockhash', code) else 0.0
    elif vuln_type == "integer_overflow":
        p[0] = 1.0 if re.search(r'\bunchecked\b', code) else 0.0
        p[1] = 0.0 if re.search(r'SafeMath|safeAdd|safeSub|safeMul', code) else 1.0
        p[2] = 1.0 if re.search(r'uint8\s*\w+\s*=\s*uint8\(|uint16', code) else 0.0
    return p
