"""M1 Tier-1 — fast regex pass."""
from pathlib import Path

from backend.scanners.source.tier1 import scan_file
from backend.scanners.source import config as signals_config

FIXTURE = Path(__file__).resolve().parents[2] / "seed_corpus" / "python" / "real_findings.py"


def setup_function(_fn):
    signals_config.reset_cache()


def test_tier1_finds_known_algorithms(scan_target_id):
    findings = scan_file(FIXTURE, scan_target_id=scan_target_id)
    primitives = {f.detectedPrimitive for f in findings}
    assert "SHA1" in primitives
    assert "MD5" in primitives
    assert "RSA-2048" in primitives
    assert any(p.startswith("AES") for p in primitives)


def test_tier1_emits_only_regex_tier(scan_target_id):
    findings = scan_file(FIXTURE, scan_target_id=scan_target_id)
    assert findings, "expected at least one Tier-1 finding"
    assert all(f.detectionTier == "regex" for f in findings)
    assert all(f.sourceModule == "M1_source_scanner" for f in findings)


def test_tier1_extracts_key_size(scan_target_id):
    findings = scan_file(FIXTURE, scan_target_id=scan_target_id)
    rsa = [f for f in findings if f.detectedPrimitive == "RSA-2048"]
    assert rsa, "expected an RSA-2048 finding"
    assert all(f.keySizeBits == 2048 for f in rsa)
