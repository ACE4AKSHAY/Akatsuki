"""M1 public entrypoint — scan a repository directory for crypto usage.

`scan_repository(path, scan_target_id) -> list[RawFinding]` runs Tier-1
over every candidate source file under `path`, then runs Tier-2 only on
files that produced at least one Tier-1 hit. Returns the final AST-
confirmed (where possible) findings with `sourceModule="M1_source_scanner"`
and the supplied `scanTargetId` stamped.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from backend.scanners._finding import RawFinding
from backend.scanners.source.tier1 import iter_source_files, scan_file
from backend.scanners.source.tier2 import confirm


def _gather_tier1(root: Path, scan_target_id: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    for f in iter_source_files(root):
        out.extend(scan_file(f, scan_target_id=scan_target_id))
    return out


def scan_repository(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    """Run M1 (Tier-1 + Tier-2) over `path` and return confirmed findings."""
    root = Path(path)
    if not root.exists():
        return []
    t1 = _gather_tier1(root, scan_target_id)
    return confirm(t1)
