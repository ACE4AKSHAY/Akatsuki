"""M1 Tier-2 — tree-sitter AST confirmation."""
from pathlib import Path

from backend.scanners.source.tier1 import scan_file
from backend.scanners.source.tier2 import confirm

LANG_FIXTURES = {
    "python": "python/real_findings.py",
    "java": "java/RealFindings.java",
    "javascript": "javascript/real_findings.js",
    "go": "go/real_findings.go",
}

FP_FIXTURES = {
    "python": "python/fp_trap.py",
    "java": "java/FPTrap.java",
    "javascript": "javascript/fp_trap.js",
    "go": "go/fp_trap.go",
}

SEED = Path(__file__).resolve().parents[2] / "seed_corpus"


def test_tier2_confirms_real_findings(scan_target_id):
    for lang, rel in LANG_FIXTURES.items():
        findings = confirm(scan_file(SEED / rel, scan_target_id=scan_target_id))
        assert findings, f"expected AST-confirmed findings for {lang}"
        assert all(f.detectionTier == "ast" for f in findings), lang


def test_tier2_drops_fp_traps(scan_target_id):
    for lang, rel in FP_FIXTURES.items():
        findings = confirm(scan_file(SEED / rel, scan_target_id=scan_target_id))
        assert findings == [], f"FP-trap {lang} should yield zero findings, got {len(findings)}"


def test_tier2_extracts_aes_mode(scan_target_id):
    findings = confirm(scan_file(SEED / "java/RealFindings.java",
                                 scan_target_id=scan_target_id))
    aes = [f for f in findings if f.detectedPrimitive == "AES"]
    assert aes, "expected at least one AES finding"
    assert any(f.mode == "ECB" for f in aes)
