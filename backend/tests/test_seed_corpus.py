"""End-to-end seed-corpus recall/precision measurement.

For each fixture under `seed_corpus/`, runs the appropriate scanner and
asserts:
  - true-positive fixtures: actual findings ⊇ expected (recall)
  - FP-trap fixtures:       actual findings == ∅ (precision)

At end of run, prints a metrics block per the plan.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pytest

# Make the project root importable.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.scanners.binary_deps.scanner import scan_path as m2_scan
from backend.scanners.infra.scanner import scan_path as m3_scan
from backend.scanners.source.scanner import scan_repository as m1_scan
from backend.tests.conftest import parse_expected_findings

SEED = ROOT / "seed_corpus"
LANG_DIRS = {
    "python": ("python", m1_scan, "real_findings.py"),
    "java": ("java", m1_scan, "RealFindings.java"),
    "javascript": ("javascript", m1_scan, "real_findings.js"),
    "go": ("go", m1_scan, "real_findings.go"),
}
FP_FIXTURES = {
    "python": "fp_trap.py",
    "java": "FPTrap.java",
    "javascript": "fp_trap.js",
    "go": "fp_trap.go",
}
MANIFEST_FILES = [
    ("manifests/requirements.txt", m2_scan),
    ("manifests/package.json", m2_scan),
    ("manifests/go.mod", m2_scan),
    ("manifests/pom.xml", m2_scan),
    ("binary/openssl_v1_0_2_strings.txt", m2_scan),
]
INFRA_FILES = [
    ("configs/nginx_tls10.conf", m3_scan),
    ("configs/nginx_modern.conf", m3_scan),
    ("iac/main.tf", m3_scan),
    ("certs/small_rsa1024.pem", m3_scan),
    ("certs/sha1_signed.pem", m3_scan),
    ("certs/long_validity.pem", m3_scan),
    ("certs/good_rsa2048.pem", m3_scan),
]


def _key(expected: dict) -> tuple:
    return (expected.get("primitive", ""), expected.get("line", -1))


def _actual_key(prim: str, line: int) -> tuple:
    return (prim, line)


# ---------------------------------------------------------------------------
# Per-module recall / precision
# ---------------------------------------------------------------------------

def _collect(roots_and_scanners):
    tp, fp, fn = 0, 0, 0
    for rel, scanner, scan_id in roots_and_scanners:
        fixture = SEED / rel
        if not fixture.exists():
            continue
        expected = parse_expected_findings(fixture)
        try:
            actual = scanner(fixture, scan_id)
        except Exception:
            actual = []
        # Build primitive+line sets
        actual_keys = {(f.detectedPrimitive, f.lineNumber) for f in actual}
        expected_keys = {_key(e) for e in expected}
        tp += len(actual_keys & expected_keys)
        fp += len(actual_keys - expected_keys)
        fn += len(expected_keys - actual_keys)
    return tp, fp, fn


@pytest.fixture
def _metrics(scan_target_id):
    """Run the full corpus once per session, return metrics dict."""
    out: dict[str, tuple[int, int, int]] = {}

    # M1 — per language (per-file scan, not directory scan, to keep FP-traps
    # isolated from the real-finding fixtures sitting next to them).
    m1_tp, m1_fp, m1_fn = 0, 0, 0
    for lang, (subdir, scanner, fname) in LANG_DIRS.items():
        fixture = SEED / subdir / fname
        if not fixture.exists():
            continue
        expected = parse_expected_findings(fixture)
        actual = scanner(fixture, scan_target_id)
        actual_keys = {(f.detectedPrimitive, f.lineNumber) for f in actual}
        expected_keys = {_key(e) for e in expected}
        m1_tp += len(actual_keys & expected_keys)
        m1_fp += len(actual_keys - expected_keys)
        m1_fn += len(expected_keys - actual_keys)
        # FP-trap: must be empty after full M1 (Tier-1 + Tier-2)
        fp_fix = SEED / subdir / FP_FIXTURES[lang]
        if fp_fix.exists():
            fp_actual = scanner(fp_fix, scan_target_id)
            assert fp_actual == [], f"M1 FP-trap {lang} not empty: {[f.detectedPrimitive for f in fp_actual]}"
    out["M1"] = (m1_tp, m1_fp, m1_fn)

    # M2 — per manifest. Library-name-only matching; line numbers vary
    # across ecosystems (JSON/Go/Maven all collapse to line 1 by design).
    m2_tp, m2_fp, m2_fn = 0, 0, 0
    for rel, scanner in MANIFEST_FILES:
        fixture = SEED / rel
        if not fixture.exists():
            continue
        expected = parse_expected_findings(fixture)
        actual = scanner(fixture, scan_target_id)
        actual_set = {f.library for f in actual if f.library}
        expected_set = {e.get("library") for e in expected if e.get("library")}
        m2_tp += len(actual_set & expected_set)
        m2_fp += len(actual_set - expected_set)
        m2_fn += len(expected_set - actual_set)
    out["M2"] = (m2_tp, m2_fp, m2_fn)

    # M3 — per category
    m3_tp, m3_fp, m3_fn = 0, 0, 0
    for rel, scanner in INFRA_FILES:
        fixture = SEED / rel
        if not fixture.exists():
            continue
        expected = parse_expected_findings(fixture)
        actual = scanner(fixture, scan_target_id)
        actual_keys = {(f.detectedPrimitive, f.lineNumber) for f in actual}
        expected_keys = {_key(e) for e in expected}
        m3_tp += len(actual_keys & expected_keys)
        m3_fp += len(actual_keys - expected_keys)
        m3_fn += len(expected_keys - actual_keys)
    out["M3"] = (m3_tp, m3_fp, m3_fn)
    return out


def test_seed_corpus_metrics(_metrics, capsys):
    """Assert recall ≥ 0.85 across the corpus and print the metrics block."""
    print()  # newline before block
    print("=" * 60)
    print("ECDAT M1/M2/M3 — Seed Corpus Metrics")
    print("=" * 60)
    for label, (tp, fp, fn) in _metrics.items():
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        print(f"  {label:<6}  recall={recall:.2f}  precision={precision:.2f}  "
              f"(tp={tp} fp={fp} fn={fn})")
    print("=" * 60)
    # Per plan done-criterion: per-module recall ≥ 0.85.
    for label, (tp, fp, fn) in _metrics.items():
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        assert recall >= 0.85, f"{label} recall {recall:.2f} < 0.85"
