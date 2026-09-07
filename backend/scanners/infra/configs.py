"""M3 configs sub-scanner.

Walks a path for nginx/httpd/`*.conf`/`application.yml` files. Extracts
  - `ssl_protocols` — flags SSLv2/SSLv3/TLSv1/TLSv1.1 as deprecated
  - `ssl_ciphers`    — flags RC4/DES-CBC3/EXPORT/NULL/aNULL/eNULL

Emits RawFindings with `detectionTier="config-parse"`, `confidence=0.95`.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from backend.scanners._finding import RawFinding
from backend.scanners.binary_deps.manifests import _strip_expected_header

CONFIG_NAMES = ("nginx", "httpd")
CONFIG_EXTS = (".conf", ".yml", ".yaml")

PROTOCOL_LINE_RE = re.compile(r"^\s*ssl_protocols\s+([^\n;]+)", re.IGNORECASE | re.MULTILINE)
CIPHER_LINE_RE = re.compile(r"^\s*ssl_ciphers\s+([^\n;]+)", re.IGNORECASE | re.MULTILINE)

DEPRECATED_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
WEAK_CIPHERS = ("RC4", "DES-CBC3", "EXPORT", "NULL", "aNULL", "eNULL")


def _is_config_file(p: Path) -> bool:
    name = p.name.lower()
    if any(name.startswith(n) for n in CONFIG_NAMES):
        return True
    if p.suffix.lower() in CONFIG_EXTS:
        return True
    return False


def _iter_configs(root: Path) -> Iterable[Path]:
    if root.is_file():
        if _is_config_file(root):
            yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and _is_config_file(p):
            yield p


def _line_no_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_file(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    p = Path(path)
    if not p.is_file():
        return []
    out: list[RawFinding] = []
    text = _strip_expected_header(p.read_text(encoding="utf-8", errors="replace"))
    for m in PROTOCOL_LINE_RE.finditer(text):
        line_no = _line_no_at(text, m.start())
        protocols = m.group(1).split()
        for proto in protocols:
            proto = proto.rstrip(";")
            if proto in DEPRECATED_PROTOCOLS:
                out.append(RawFinding(
                    sourceModule="M3_container_config_scanner",
                    scanTargetId=scan_target_id,
                    filePath=str(p),
                    lineNumber=line_no,
                    language=None,
                    library=None,
                    rawSignal=f"ssl_protocols ... {proto}",
                    detectedPrimitive=proto,
                    primitiveCategory="protocol",
                    keySizeBits=None,
                    mode="deprecated",
                    confidence=0.95,
                    detectionTier="config-parse",
                ))
    for m in CIPHER_LINE_RE.finditer(text):
        line_no = _line_no_at(text, m.start())
        ciphers = m.group(1)
        for weak in WEAK_CIPHERS:
            if weak in ciphers:
                out.append(RawFinding(
                    sourceModule="M3_container_config_scanner",
                    scanTargetId=scan_target_id,
                    filePath=str(p),
                    lineNumber=line_no,
                    language=None,
                    library=None,
                    rawSignal=f"ssl_ciphers ... {weak}",
                    detectedPrimitive=weak,
                    primitiveCategory="cipher",
                    keySizeBits=None,
                    mode="weak",
                    confidence=0.95,
                    detectionTier="config-parse",
                ))
    return out


def scan_configs(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    """Walk `path` and run the config scanner over each match."""
    root = Path(path)
    if not root.exists():
        return []
    out: list[RawFinding] = []
    for f in _iter_configs(root):
        out.extend(scan_file(f, scan_target_id))
    return out
