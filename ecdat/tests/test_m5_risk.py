"""Unit tests for M5 Quantum Risk Assessment Engine."""

import pytest
from backend.engine.normalizer import normalize
from backend.engine.risk import is_classically_broken, score_asset, score_assets
from backend.models.schemas import RawFinding, ThreatModelConfig


def test_mosca_worked_examples_section_9_4():
    """Reproduce the exact worked example table in Section 9.4 of the design doc."""
    tm = ThreatModelConfig(threatTimelineYears=8.0)

    # Example 1: Customer PII field encryption - RSA-2048 key exchange (X=15, Y=1.5, Z=8 -> r=2.06 -> Critical)
    raw_pii = RawFinding(
        sourceModule="M1_source_scanner",
        scanTargetId="scan_test",
        filePath="src/pii/encryptor.py",
        lineNumber=10,
        language="python",
        library="pyca/cryptography",
        rawSignal="RSA.generate(2048)",
        detectedPrimitive="RSA",
        primitiveCategory="key-exchange",
        keySizeBits=2048,
        mode=None,
        confidence=0.95,
        detectionTier="ast",
    )
    assets_pii = normalize([raw_pii], tagging_config={
        "*pii*": {
            "businessCriticality": "High",
            "dataClassification": "Customer-PII",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 15.0,
            "estimatedMigrationEffortYears": 1.5,
        }
    })
    scored_pii = score_asset(assets_pii[0], threat_model=tm)
    enr_pii = scored_pii.ecdatEnrichment

    assert enr_pii.moscaX == 15.0
    assert enr_pii.moscaY == 1.5
    assert enr_pii.moscaZ == 8.0
    assert enr_pii.moscaR == 2.06
    assert enr_pii.moscaRiskTier == "Critical"

    # Example 2: Internal microservice mTLS - ECDSA-P256 cert (X=3, Y=0.5, Z=8 -> r=0.44 -> Low)
    raw_mtls = RawFinding(
        sourceModule="M3_container_config_scanner",
        scanTargetId="scan_test",
        filePath="config/internal/mtls.crt",
        lineNumber=1,
        language="asn1",
        library="cryptography",
        rawSignal="ECDSA_P256",
        detectedPrimitive="ECDSA",
        primitiveCategory="signature",
        keySizeBits=256,
        mode=None,
        confidence=1.0,
        detectionTier="cert-parse",
    )
    assets_mtls = normalize([raw_mtls], tagging_config={
        "*internal*": {
            "businessCriticality": "Medium",
            "dataClassification": "Internal-Data",
            "exposure": "internal-only",
            "estimatedShelfLifeYears": 3.0,
            "estimatedMigrationEffortYears": 0.5,
        }
    })
    scored_mtls = score_asset(assets_mtls[0], threat_model=tm)
    enr_mtls = scored_mtls.ecdatEnrichment

    assert enr_mtls.moscaX == 3.0
    assert enr_mtls.moscaY == 0.5
    assert enr_mtls.moscaZ == 8.0
    assert enr_mtls.moscaR == 0.44
    assert enr_mtls.moscaRiskTier == "Low"

    # Example 3: Firmware signing - RSA-2048 signature (X=10, Y=2, Z=8 -> r=1.5 -> Critical)
    raw_firmware = RawFinding(
        sourceModule="M1_source_scanner",
        scanTargetId="scan_test",
        filePath="src/firmware/signer.py",
        lineNumber=50,
        language="python",
        library="pyca/cryptography",
        rawSignal="rsa.sign()",
        detectedPrimitive="RSA-PSS",
        primitiveCategory="signature",
        keySizeBits=2048,
        mode=None,
        confidence=0.9,
        detectionTier="ast",
    )
    assets_firmware = normalize([raw_firmware], tagging_config={
        "*firmware*": {
            "businessCriticality": "Critical",
            "dataClassification": "Firmware-Signing",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 10.0,
            "estimatedMigrationEffortYears": 2.0,
        }
    })
    scored_firmware = score_asset(assets_firmware[0], threat_model=tm)
    enr_firmware = scored_firmware.ecdatEnrichment

    assert enr_firmware.moscaX == 10.0
    assert enr_firmware.moscaY == 2.0
    assert enr_firmware.moscaZ == 8.0
    assert enr_firmware.moscaR == 1.5
    assert enr_firmware.moscaRiskTier == "Critical"

    # Example 4: Session token hashing - SHA-1 (auto-escalated -> Critical regardless of ratio)
    raw_sha1 = RawFinding(
        sourceModule="M1_source_scanner",
        scanTargetId="scan_test",
        filePath="src/session/hasher.py",
        lineNumber=25,
        language="python",
        library="hashlib",
        rawSignal="hashlib.sha1()",
        detectedPrimitive="SHA1",
        primitiveCategory="hash",
        keySizeBits=None,
        mode=None,
        confidence=0.95,
        detectionTier="ast",
    )
    assets_sha1 = normalize([raw_sha1], tagging_config={
        "*session*": {
            "businessCriticality": "Low",
            "dataClassification": "Session",
            "exposure": "internal-only",
            "estimatedShelfLifeYears": 0.1,
            "estimatedMigrationEffortYears": 0.1,
        }
    })
    scored_sha1 = score_asset(assets_sha1[0], threat_model=tm)
    enr_sha1 = scored_sha1.ecdatEnrichment

    assert enr_sha1.moscaRiskTier == "Critical", "Classically broken SHA-1 must auto-escalate to Critical"
    assert enr_sha1.autoEscalated is True
    assert "classically broken" in enr_sha1.vulnerabilityReason


def test_classically_broken_auto_escalation():
    """Verify all classically broken algorithms are auto-escalated to Critical."""
    for algo in ["MD5", "sha-1", "DES", "3DES", "RC4", "blowfish"]:
        assert is_classically_broken(algo) is True
