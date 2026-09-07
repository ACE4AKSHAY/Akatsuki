"""M2 manifest parsers — pip, npm, go.mod, Maven pom.xml.

Each parser returns a list of RawFinding with
  sourceModule="M2_dep_binary_scanner"
  detectionTier="manifest"
  confidence=0.85
  lineNumber=1

Only libraries present in the crypto-library registry produce findings
(harmless libs like `requests`/`lodash`/etc. are intentionally ignored
to keep precision high — they're in the registry with empty `algorithms`).
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable

from backend.scanners._finding import RawFinding
from backend.scanners.binary_deps.registry import lookup


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------

_REQ_RE = re.compile(r"^\s*([\w\-\.\/]+)\s*([=<>~!]=)\s*([\w\-\.\+]+)\s*$")


def _strip_expected_header(text: str) -> str:
    """Remove a leading `# EXPECTED_FINDINGS: ...` (or `//` for JSON/Go) line
    that the test harness injects so the file still parses as a real manifest.
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    skipped = False
    for line in lines:
        if not skipped and (line.lstrip().startswith("# EXPECTED_FINDINGS:")
                            or line.lstrip().startswith("// EXPECTED_FINDINGS:")):
            skipped = True
            continue
        out.append(line)
    return "".join(out)


def parse_requirements_txt(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    p = Path(path)
    if not p.is_file():
        return []
    out: list[RawFinding] = []
    text = _strip_expected_header(p.read_text(encoding="utf-8", errors="replace"))
    for line_no, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        name, _op, version = m.group(1), m.group(2), m.group(3)
        entry = lookup(name, "pypi", version)
        if entry is None or not entry.get("algorithms"):
            continue
        out.append(_build_manifest_finding(
            scan_target_id=scan_target_id,
            file_path=str(p),
            line_no=line_no,
            name=name,
            version=version,
            entry=entry,
            language="manifest",
        ))
    return out


# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------

def parse_package_json(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    p = Path(path)
    if not p.is_file():
        return []
    try:
        data = json.loads(_strip_expected_header(p.read_text(encoding="utf-8", errors="replace")))
    except json.JSONDecodeError:
        return []
    out: list[RawFinding] = []
    deps = {}
    deps.update(data.get("dependencies", {}) or {})
    deps.update(data.get("devDependencies", {}) or {})
    for name, version in deps.items():
        if not isinstance(version, str):
            continue
        entry = lookup(name, "npm", version.lstrip("^~>=<"))
        if entry is None or not entry.get("algorithms"):
            continue
        out.append(_build_manifest_finding(
            scan_target_id=scan_target_id,
            file_path=str(p),
            line_no=1,
            name=name,
            version=version,
            entry=entry,
            language="manifest",
        ))
    return out


# ---------------------------------------------------------------------------
# go.mod
# ---------------------------------------------------------------------------

_GO_REQUIRE_LINE = re.compile(r"^\s*(\S+)\s+(\S+)\s*$")


def parse_go_mod(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    p = Path(path)
    if not p.is_file():
        return []
    out: list[RawFinding] = []
    in_require = False
    text = _strip_expected_header(p.read_text(encoding="utf-8", errors="replace"))
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if not in_require:
            continue
        # skip single-line `require foo v1.2.3`
        if stripped.startswith("require "):
            stripped = stripped[len("require "):].strip()
        m = _GO_REQUIRE_LINE.match(stripped)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        if name == "//" or version.startswith("//"):
            continue
        entry = lookup(name, "go", version.lstrip("v"))
        if entry is None or not entry.get("algorithms"):
            continue
        out.append(_build_manifest_finding(
            scan_target_id=scan_target_id,
            file_path=str(p),
            line_no=1,
            name=name,
            version=version,
            entry=entry,
            language="go-mod",
        ))
    return out


# ---------------------------------------------------------------------------
# pom.xml
# ---------------------------------------------------------------------------

def parse_pom_xml(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    p = Path(path)
    if not p.is_file():
        return []
    try:
        root = ET.fromstring(_strip_expected_header(p.read_text(encoding="utf-8", errors="replace")))
    except ET.ParseError:
        return []
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0] + "}"
    out: list[RawFinding] = []
    for dep in root.iter(ns + "dependency"):
        artifact = dep.find(ns + "artifactId")
        if artifact is None or not artifact.text:
            continue
        name = artifact.text.strip()
        version_el = dep.find(ns + "version")
        version = version_el.text.strip() if version_el is not None and version_el.text else ""
        entry = lookup(name, "maven", version)
        if entry is None or not entry.get("algorithms"):
            continue
        out.append(_build_manifest_finding(
            scan_target_id=scan_target_id,
            file_path=str(p),
            line_no=1,
            name=name,
            version=version,
            entry=entry,
            language="manifest",
        ))
    return out


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def parse_manifest(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    """Dispatch a single manifest file to the right parser by name."""
    name = Path(path).name.lower()
    if name == "requirements.txt":
        return parse_requirements_txt(path, scan_target_id)
    if name.startswith("package") and name.endswith(".json"):
        return parse_package_json(path, scan_target_id)
    if name == "go.mod":
        return parse_go_mod(path, scan_target_id)
    if name == "pom.xml":
        return parse_pom_xml(path, scan_target_id)
    return []


def _build_manifest_finding(*, scan_target_id: str, file_path: str, line_no: int,
                            name: str, version: str, entry: dict,
                            language: str) -> RawFinding:
    raw = f"{name}=={version}" if version else name
    detected_primitive = entry["library"]
    if entry.get("deprecated"):
        raw = f"{raw} (DEPRECATED)"
    return RawFinding(
        sourceModule="M2_dep_binary_scanner",
        scanTargetId=scan_target_id,
        filePath=file_path,
        lineNumber=line_no,
        language=language,
        library=entry["library"],
        rawSignal=raw,
        detectedPrimitive=detected_primitive,
        primitiveCategory="key-management",
        keySizeBits=None,
        mode=None,
        confidence=0.85,
        detectionTier="manifest",
    )