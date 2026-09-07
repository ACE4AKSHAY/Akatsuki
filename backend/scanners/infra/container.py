"""M3 container sub-scanner.

`scan_dockerfile(path)` — extract `FROM`, `RUN apt-get install ...`,
`RUN pip install ...`, `RUN npm install ...` lines; cross-reference installed
packages against the M2 crypto library registry; emit RawFindings with
`detectionTier="dockerfile"`, `confidence=0.85`.

`scan_container_image(ref)` — NotImplementedError (Trivy shell-out is
roadmap §17, not 1-day deliverable). Per the plan, this is intentionally
NOT a stub returning []; raising makes the gap visible.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from backend.scanners._finding import RawFinding
from backend.scanners.binary_deps.registry import lookup
from backend.scanners.binary_deps.manifests import _strip_expected_header

FROM_RE = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE)
RUN_APT_RE = re.compile(r"^\s*RUN\s+.*?apt-get\s+install[^\n]*", re.IGNORECASE)
RUN_PIP_RE = re.compile(r"^\s*RUN\s+.*?pip(?:3)?\s+install[^\n]*", re.IGNORECASE)
RUN_NPM_RE = re.compile(r"^\s*RUN\s+.*?npm\s+install[^\n]*", re.IGNORECASE)
PKG_TOKEN_RE = re.compile(r"([\w\-\.]+)\s*([=<>~!]=)?\s*([\w\-\.\+]+)?")


def _emit_installs(packages: Iterable[str], *, scan_target_id: str, file_path: str,
                   line_no: int) -> list[RawFinding]:
    out: list[RawFinding] = []
    for pkg in packages:
        name = pkg.strip().strip("\"'")
        if not name or name in {"install", "&&", "\\", "-y", "--no-install-recommends"}:
            continue
        for entry in lookup(name) or []:
            pass
        entry = lookup(name)
        if entry is None or not entry.get("algorithms"):
            continue
        out.append(RawFinding(
            sourceModule="M3_container_config_scanner",
            scanTargetId=scan_target_id,
            filePath=file_path,
            lineNumber=line_no,
            language="manifest",
            library=entry["library"],
            rawSignal=f"install {name}",
            detectedPrimitive=entry["library"],
            primitiveCategory="key-management",
            keySizeBits=None,
            mode=None,
            confidence=0.85,
            detectionTier="dockerfile",
        ))
    return out


def scan_dockerfile(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    p = Path(path)
    if not p.is_file():
        return []
    out: list[RawFinding] = []
    text = _strip_expected_header(p.read_text(encoding="utf-8", errors="replace"))
    for line_no, line in enumerate(text.splitlines(), 1):
        m = FROM_RE.match(line)
        if m:
            base = m.group(1)
            out.append(RawFinding(
                sourceModule="M3_container_config_scanner",
                scanTargetId=scan_target_id,
                filePath=str(p),
                lineNumber=line_no,
                language="manifest",
                library=None,
                rawSignal=f"FROM {base}",
                detectedPrimitive="base-image",
                primitiveCategory="key-management",
                keySizeBits=None,
                mode=None,
                confidence=0.7,
                detectionTier="dockerfile",
            ))
            continue
        for rx in (RUN_APT_RE, RUN_PIP_RE, RUN_NPM_RE):
            if rx.match(line):
                # Pull every token that *looks like* a package name (letters,
                # digits, -, ., _, starting with letter, not a flag).
                pkgs = re.findall(r"\b([A-Za-z][\w\-\.]*[A-Za-z0-9])\b", line)
                out.extend(_emit_installs(pkgs, scan_target_id=scan_target_id,
                                          file_path=str(p), line_no=line_no))
                break
    return out


def scan_container_image(image_ref: str) -> list[RawFinding]:  # pragma: no cover
    """Intentionally raises — roadmap §17 (Trivy shell-out).

    Per the plan this is NOT a stub returning []; the dispatcher caller
    needs to know the gap is real. Implement with Trivy / Syft / Grype
    shell-out in a follow-up.
    """
    raise NotImplementedError(
        "M3 scan_container_image is roadmap §17 (Trivy shell-out), "
        "not part of the 1-day MVP. See ECDAT_Design_and_Technical_Document.md §17."
    )