"""Crypto-library registry — small loader/lookup module.

`lookup(library, ecosystem, version) -> dict | None` returns the registry
entry whose `match_names` includes the given library name. Version is
consulted against `deprecated_ranges` to flag deprecated usage.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_REGISTRY_PATH = Path(__file__).with_name("registry.json")


@lru_cache(maxsize=1)
def _load() -> dict:
    return json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))


def _version_deprecated(version: str, ranges: list[str]) -> bool:
    if not version or not ranges:
        return False
    for r in ranges:
        if _version_in_range(version, r):
            return True
    return False


def _version_in_range(version: str, expr: str) -> bool:
    """Tiny PEP 440-ish range check supporting <X, <=X, >X, >=X, ==X."""
    m = re.match(r"^\s*(<=|>=|<|>|==|!=)\s*(\d[\w\.\-\+]*)\s*$", expr)
    if not m:
        return False
    op, target = m.group(1), m.group(2)
    try:
        from packaging.version import Version
        v = Version(version)
        t = Version(target)
    except Exception:
        return False
    if op == "<":  return v < t
    if op == "<=": return v <= t
    if op == ">":  return v > t
    if op == ">=": return v >= t
    if op == "==": return v == t
    if op == "!=": return v != t
    return False


def lookup(library: str, ecosystem: str = "", version: str = "") -> dict | None:
    """Return the registry entry that matches `library` (or None).

    Match rules:
      - exact match against `library` or any name in `match_names`
      - ecosystem must match (or be empty) when provided
    """
    if not library:
        return None
    lib_lower = library.strip().lower()
    for entry in _load().get("libraries", []):
        names = [entry.get("library", "")] + entry.get("match_names", [])
        if lib_lower in {n.lower() for n in names}:
            if ecosystem and entry.get("ecosystem") and entry["ecosystem"] != ecosystem:
                continue
            result = dict(entry)
            result["deprecated"] = _version_deprecated(version, entry.get("deprecated_ranges", []))
            return result
    return None


def all_libraries() -> list[dict]:
    """Return the raw list of library entries (for tests/diagnostics)."""
    return list(_load().get("libraries", []))


def reset_cache() -> None:
    _load.cache_clear()