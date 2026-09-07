"""M3 IaC sub-scanner — Terraform HCL.

Tries `python-hcl2` first; falls back to regex extraction of resource
blocks (allowed by design doc §19 prompt 3). Detects `aws_kms_key`,
`azurerm_key_vault_key`, `google_kms_key_ring` blocks. Extracts
key_spec / algorithm / protection_level where present.

Emits RawFindings with `detectionTier="iac-parse"`, `confidence=0.9`.
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path
from typing import Iterable

from backend.scanners._finding import RawFinding
from backend.scanners.binary_deps.manifests import _strip_expected_header

KMS_RESOURCES = ("aws_kms_key", "azurerm_key_vault_key", "google_kms_key_ring")

HCL2 = None
try:
    importlib.import_module("hcl2")
    HCL2 = True
except ImportError:
    HCL2 = False

_RESOURCE_RE = re.compile(
    r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{(.*?)^\s*\}',
    re.DOTALL | re.MULTILINE,
)
_KEY_SPEC_RE = re.compile(r'^\s*key_spec\s*=\s*"([^"]+)"', re.MULTILINE)
_ALGORITHM_RE = re.compile(r'^\s*algorithm\s*=\s*"([^"]+)"', re.MULTILINE)
_PROTECTION_RE = re.compile(r'^\s*protection_level\s*=\s*"([^"]+)"', re.MULTILINE)
_KEY_TYPE_RE = re.compile(r'^\s*key_type\s*=\s*"([^"]+)"', re.MULTILINE)
_KEY_SIZE_RE = re.compile(r'^\s*key_size\s*=\s*(\d+)', re.MULTILINE)


def _is_iac_file(p: Path) -> bool:
    return p.suffix.lower() == ".tf"


def _iter_iac(root: Path) -> Iterable[Path]:
    if root.is_file():
        if _is_iac_file(root):
            yield root
        return
    for p in root.rglob("*.tf"):
        if p.is_file():
            yield p


def _emit_kms(resource: str, attrs: dict, *, scan_target_id: str,
              file_path: str, line_no: int) -> RawFinding:
    raw = f'resource "{resource}"'
    if attrs:
        raw += " " + " ".join(f'{k}={v}' for k, v in attrs.items())
    return RawFinding(
        sourceModule="M3_container_config_scanner",
        scanTargetId=scan_target_id,
        filePath=file_path,
        lineNumber=line_no,
        language=None,
        library=None,
        rawSignal=raw,
        detectedPrimitive=resource,
        primitiveCategory="key-management",
        keySizeBits=attrs.get("key_size"),
        mode=attrs.get("key_spec") or attrs.get("algorithm") or attrs.get("key_type"),
        confidence=0.9,
        detectionTier="iac-parse",
    )


def _line_no_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_file(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    p = Path(path)
    if not p.is_file():
        return []
    out: list[RawFinding] = []
    text = _strip_expected_header(p.read_text(encoding="utf-8", errors="replace"))

    if HCL2:
        try:
            import hcl2
            data = hcl2.load(open(p, "r", encoding="utf-8"))
            # hcl2 returns a dict like {"resource": {"aws_kms_key": {"a": {...}}}}
            resources = data.get("resource", {}) or {}
            for kind, named in resources.items():
                if kind not in KMS_RESOURCES:
                    continue
                for instance_name, attrs in (named or {}).items():
                    attrs_flat = {k: v for k, v in (attrs or {}).items()}
                    # Look for key_size / algorithm / key_spec / protection_level
                    ks = attrs_flat.get("key_size")
                    out.append(_emit_kms(
                        kind,
                        {
                            "key_size": str(ks) if ks is not None else None,
                            "algorithm": attrs_flat.get("algorithm"),
                            "key_spec": attrs_flat.get("key_spec"),
                            "key_type": attrs_flat.get("key_type"),
                            "protection_level": attrs_flat.get("protection_level"),
                        },
                        scan_target_id=scan_target_id,
                        file_path=str(p),
                        line_no=1,
                    ))
            return out
        except Exception:
            pass  # fall through to regex

    # Regex fallback
    for m in _RESOURCE_RE.finditer(text):
        resource = m.group(1)
        if resource not in KMS_RESOURCES:
            continue
        body = m.group(3)
        attrs: dict = {}
        for rx, key in (
            (_KEY_SPEC_RE, "key_spec"),
            (_ALGORITHM_RE, "algorithm"),
            (_PROTECTION_RE, "protection_level"),
            (_KEY_TYPE_RE, "key_type"),
            (_KEY_SIZE_RE, "key_size"),
        ):
            sub = rx.search(body)
            if sub:
                attrs[key] = sub.group(1)
        out.append(_emit_kms(
            resource, attrs,
            scan_target_id=scan_target_id,
            file_path=str(p),
            line_no=_line_no_at(text, m.start()),
        ))
    return out


def scan_iac(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    root = Path(path)
    if not root.exists():
        return []
    out: list[RawFinding] = []
    for f in _iter_iac(root):
        out.extend(scan_file(f, scan_target_id))
    return out
