"""M3 IaC sub-scanner — Terraform KMS resources."""
from pathlib import Path

from backend.scanners.infra.iac import scan_iac

SEED = Path(__file__).resolve().parents[2] / "seed_corpus" / "iac"


def test_kms_resources_detected(scan_target_id):
    findings = scan_iac(SEED / "main.tf", scan_target_id)
    prims = {f.detectedPrimitive for f in findings}
    assert "aws_kms_key" in prims
    assert "azurerm_key_vault_key" in prims
    assert "google_kms_key_ring" in prims


def test_azurerm_key_size_extracted(scan_target_id):
    findings = scan_iac(SEED / "main.tf", scan_target_id)
    az = [f for f in findings if f.detectedPrimitive == "azurerm_key_vault_key"]
    assert az
    assert any(f.keySizeBits == 2048 for f in az)
