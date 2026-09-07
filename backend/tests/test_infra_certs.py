"""M3 certs sub-scanner — X.509 rules."""
from pathlib import Path

from backend.scanners.infra.certs import scan_certificates

SEED = Path(__file__).resolve().parents[2] / "seed_corpus" / "certs"


def test_small_rsa_key_flagged(scan_target_id):
    findings = scan_certificates(SEED / "small_rsa1024.pem", scan_target_id)
    prims = {f.detectedPrimitive for f in findings}
    assert "RSA-1024" in prims


def test_sha1_sig_flagged(scan_target_id):
    findings = scan_certificates(SEED / "sha1_signed.pem", scan_target_id)
    prims = {f.detectedPrimitive for f in findings}
    assert "SHA1-RSA-SIG" in prims


def test_long_validity_flagged(scan_target_id):
    findings = scan_certificates(SEED / "long_validity.pem", scan_target_id)
    prims = {f.detectedPrimitive for f in findings}
    assert "long-validity-cert" in prims


def test_good_cert_has_no_critical_flags(scan_target_id):
    findings = scan_certificates(SEED / "good_rsa2048.pem", scan_target_id)
    prims = {f.detectedPrimitive for f in findings}
    # Only self-signed (the test cert is self-signed by construction) — no
    # small-key, weak-sig, or long-validity flags.
    assert prims <= {"self-signed-cert"}
