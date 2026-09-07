"""Pytest fixtures shared across the ECDAT test suite."""
import json
import re
import sys
from pathlib import Path

import pytest

# Make `backend` importable without an editable install.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SEED = ROOT / "seed_corpus"


HEADER_RE = re.compile(
    r"^\s*(?:#|//)\s*EXPECTED_FINDINGS:\s*(\[[^\]]*\])\s*$",
    re.MULTILINE,
)


def parse_expected_findings(path):
    """Pull the EXPECTED_FINDINGS JSON array from a fixture's first line."""
    text = path.read_text(encoding="utf-8", errors="replace")
    m = HEADER_RE.search(text)
    if not m:
        return []
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return []


@pytest.fixture
def seed_corpus_root() -> Path:
    return SEED


@pytest.fixture
def scan_target_id() -> str:
    return "test_run"
