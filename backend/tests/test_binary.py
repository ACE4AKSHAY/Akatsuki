"""M2 binary strings/symbols — text-fixture strings-fallback test."""
from pathlib import Path

from backend.scanners.binary_deps.binary import scan_binary

SEED = Path(__file__).resolve().parents[2] / "seed_corpus" / "binary"


def test_strings_fallback_detects_openssl_1_0_2(scan_target_id):
    """The text fixture must produce findings via the always-works pure-Python
    strings path — no toolchain dependency."""
    findings = scan_binary(SEED / "openssl_v1_0_2_strings.txt", scan_target_id)
    primitives = {f.detectedPrimitive for f in findings}
    assert "OpenSSL 1.0.2" in primitives
    for sym in ("RSA", "MD5", "SHA1", "DES", "RC4"):
        assert sym in primitives, f"missing {sym} in findings"


def test_strings_fallback_marks_deprecated(scan_target_id):
    findings = scan_binary(SEED / "openssl_v1_0_2_strings.txt", scan_target_id)
    openssl = [f for f in findings if f.detectedPrimitive == "OpenSSL 1.0.2"]
    assert openssl
    assert any(f.mode == "deprecated" for f in openssl)
