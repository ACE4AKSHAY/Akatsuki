"""M3 configs sub-scanner — TLS protocol / cipher flags."""
from pathlib import Path

from backend.scanners.infra.configs import scan_configs

SEED = Path(__file__).resolve().parents[2] / "seed_corpus" / "configs"


def test_deprecated_protocols_flagged(scan_target_id):
    findings = scan_configs(SEED / "nginx_tls10.conf", scan_target_id)
    protos = {f.detectedPrimitive for f in findings if f.primitiveCategory == "protocol"}
    assert "TLSv1" in protos
    assert "TLSv1.1" in protos


def test_weak_cipher_flagged(scan_target_id):
    findings = scan_configs(SEED / "nginx_tls10.conf", scan_target_id)
    ciphers = {f.detectedPrimitive for f in findings if f.primitiveCategory == "cipher"}
    assert "RC4" in ciphers


def test_modern_config_clean(scan_target_id):
    findings = scan_configs(SEED / "nginx_modern.conf", scan_target_id)
    assert findings == []
