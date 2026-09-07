"""Load signals.yaml — the regex signal table for M1 Tier-1."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_SIGNALS_PATH = Path(__file__).with_name("signals.yaml")

_cache: list[dict[str, Any]] | None = None


def load_signals() -> list[dict[str, Any]]:
    """Return the list of signal entries, cached in-process."""
    global _cache
    if _cache is None:
        with _SIGNALS_PATH.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        _cache = data.get("signals", [])
    return _cache


def reset_cache() -> None:
    """Test helper: drop the in-process cache so signals.yaml re-loads."""
    global _cache
    _cache = None