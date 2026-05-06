"""
Dataset loading utilities.

Supports two data sources:

1. **DAppSCAN filtered** — the standard CCH pipeline output
   (``data/dappscan_filtered/{vuln_type}/vuln/*.sol`` + ``safe/*.sol``)
2. **Curated high-detection** — pre-filtered samples where at least one
   model detects the vulnerability
   (``data/curated/{vuln_type}/vulnerable/*.sol`` + ``non_vulnerable/*.sol``)
"""

from pathlib import Path
from typing import List, Tuple


def load_contracts(directory: Path) -> List[str]:
    """Read all ``.sol`` files from *directory*, sorted by name."""
    contracts: List[str] = []
    if not directory.exists():
        return contracts
    for f in sorted(directory.glob("*.sol")):
        try:
            contracts.append(f.read_text(encoding='utf-8'))
        except Exception:
            pass
    return contracts


def load_dataset(data_root: Path, vuln_type: str,
                 prefer_curated: bool = True) -> Tuple[List[str], List[str]]:
    """
    Load vulnerable + safe contracts for *vuln_type*.

    If *prefer_curated* is True and the curated directory exists with
    enough samples, use it; otherwise fall back to dappscan_filtered.

    Returns (vuln_contracts, safe_contracts).
    """
    curated_dir = data_root / "curated" / vuln_type
    filtered_dir = data_root / "dappscan_filtered" / vuln_type

    # Try curated first
    if prefer_curated and (curated_dir / "vulnerable").exists():
        vuln = load_contracts(curated_dir / "vulnerable")
        safe = load_contracts(curated_dir / "non_vulnerable")
        if len(vuln) >= 5:
            return vuln, safe

    # Fall back to dappscan_filtered
    vuln = load_contracts(filtered_dir / "vulnerable")
    safe = load_contracts(filtered_dir / "non_vulnerable")
    return vuln, safe
