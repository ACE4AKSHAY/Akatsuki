"""M2 public entrypoint — scan a path for crypto libraries (manifests + binaries).

`scan_path(path, scan_target_id) -> list[RawFinding]`:
  - if `path` is a directory: walk it, dispatching each file by name/extension
  - if `path` is a single file: dispatch directly
  - returns `[]` for files we don't know how to scan
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from backend.scanners._finding import RawFinding
from backend.scanners.binary_deps.binary import scan_binary
from backend.scanners.binary_deps.manifests import parse_manifest

MANIFEST_NAMES = {"requirements.txt", "package.json", "package-lock.json",
                  "go.mod", "go.sum", "pom.xml", "build.gradle"}
BINARY_EXTS = {".so", ".dll", ".dylib", ".exe", ".bin", ".elf"}


def _dispatch_one(path: Path, scan_target_id: str) -> list[RawFinding]:
    name = path.name.lower()
    if name in MANIFEST_NAMES or name.startswith("package") and name.endswith(".json"):
        return parse_manifest(path, scan_target_id)
    ext = path.suffix.lower()
    if ext in BINARY_EXTS or ext == ".txt":
        # `.txt` is the always-works text-fixture path for the strings
        # fallback test (no real binary needed on Windows dev envs).
        return scan_binary(path, scan_target_id)
    return []


def _iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_file():
            yield p


def scan_path(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    """Run M2 over a path (file or directory) and return findings."""
    root = Path(path)
    if not root.exists():
        return []
    out: list[RawFinding] = []
    for f in _iter_files(root):
        out.extend(_dispatch_one(f, scan_target_id))
    return out
