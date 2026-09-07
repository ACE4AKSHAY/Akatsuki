"""
Unit tests verifying strict compliance with ECDAT — CONTRACT.md.
Tests raw finding schema (Section 1) and canonical CBOM asset schema (Section 2).
"""
import json
import pytest
from backend.models.schemas import RawFinding, CanonicalCBOMAsset, CycloneDXDocument
from backend.engine.normalizer import build_cyclonedx_document


def test_contract_section_1_raw_finding_schema():
    """Verifies that the exact raw finding JSON from CONTRACT.md Section 1 parses and validates cleanly."""
    raw_finding_json = {
        "sourceModule": "M1_source_scanner",
        "scanTargetId": "scan_2026_09_07_abc123",
        "filePath": "src/auth/token_signer.py",
        "lineNumber": 42,
        "language": "python",
        "library": "pyca/cryptography",
        "rawSignal": "hashes.SHA1()",
        "detectedPrimitive": "SHA1",
        "primitiveCategory": "hash",
        "keySizeBits": None,
        "mode": None,
        "confidence": 0.95,
        "detectionTier": "ast",
    }

    finding = RawFinding.model_validate(raw_finding_json)

    assert finding.sourceModule == "M1_source_scanner"
    assert finding.scanTargetId == "scan_2026_09_07_abc123"
    assert finding.filePath == "src/auth/token_signer.py"
    assert finding.lineNumber == 42
    assert finding.language == "python"
    assert finding.library == "pyca/cryptography"
    assert finding.rawSignal == "hashes.SHA1()"
    assert finding.detectedPrimitive == "SHA1"
    assert finding.primitiveCategory == "hash"
    assert finding.keySizeBits is None
    assert finding.mode is None
    assert finding.confidence == 0.95
    assert finding.detectionTier == "ast"


def test_contract_section_2_canonical_cbom_asset_schema():
    """Verifies that the exact canonical CBOM asset JSON from CONTRACT.md Section 2 parses and validates cleanly."""
    canonical_asset_json = {
        "bom-ref": "crypto-asset-0af3e9",
        "type": "cryptographic-asset",
        "name": "SHA1",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "hash",
                "parameterSetIdentifier": "SHA-1",
                "executionEnvironment": "software-plain-ram",
                "implementationPlatform": "generic",
                "cryptoFunctions": ["digest"],
                "classicalSecurityLevel": 80,
                "nistQuantumSecurityLevel": 0,
            },
            "oid": "1.3.14.3.2.26",
        },
        "occurrences": [
            {"location": "src/auth/token_signer.py", "line": 42}
        ],
        "ecdatEnrichment": {
            "quantumVulnerable": True,
            "vulnerabilityReason": "classically broken (collision attacks); also loses Grover margin",
            "businessCriticality": "High",
            "dataClassification": "Authentication-Token",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 2,
            "estimatedMigrationEffortYears": 0.25,
            "moscaX": 2,
            "moscaY": 0.25,
            "moscaZ": 8,
            "moscaR": 1.34,
            "moscaRiskTier": "Critical",
            "recommendedReplacement": "SHA-384 or SHA3-384",
            "referenceStandard": "N/A (deprecate; not a PQC concern, a classical-strength concern)",
        },
    }

    asset = CanonicalCBOMAsset.model_validate(canonical_asset_json)

    assert asset.bom_ref == "crypto-asset-0af3e9"
    assert asset.type == "cryptographic-asset"
    assert asset.name == "SHA1"
    assert asset.cryptoProperties.algorithmProperties.parameterSetIdentifier == "SHA-1"
    assert asset.cryptoProperties.oid == "1.3.14.3.2.26"
    assert len(asset.occurrences) == 1
    assert asset.occurrences[0].location == "src/auth/token_signer.py"
    assert asset.occurrences[0].line == 42
    assert asset.ecdatEnrichment.quantumVulnerable is True
    assert asset.ecdatEnrichment.businessCriticality == "High"
    assert asset.ecdatEnrichment.moscaRiskTier == "Critical"
    assert asset.ecdatEnrichment.moscaR == 1.34
    assert asset.ecdatEnrichment.recommendedReplacement == "SHA-384 or SHA3-384"

    # Verify serialization preserves exact aliases like 'bom-ref'
    serialized = asset.model_dump(by_alias=True)
    assert "bom-ref" in serialized
    assert serialized["bom-ref"] == "crypto-asset-0af3e9"


def test_cyclonedx_document_generation():
    """Verifies CycloneDX 1.6 document container format."""
    canonical_asset_json = {
        "bom-ref": "crypto-asset-0af3e9",
        "type": "cryptographic-asset",
        "name": "SHA1",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "hash",
                "parameterSetIdentifier": "SHA-1",
            },
        },
        "occurrences": [],
        "ecdatEnrichment": {
            "quantumVulnerable": True,
            "vulnerabilityReason": "classically broken",
            "businessCriticality": "High",
            "dataClassification": "Authentication-Token",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 2,
            "estimatedMigrationEffortYears": 0.25,
            "moscaX": 2,
            "moscaY": 0.25,
            "moscaZ": 8,
            "moscaR": 1.34,
            "moscaRiskTier": "Critical",
            "recommendedReplacement": "SHA-384",
            "referenceStandard": "FIPS 180-4",
        },
    }
    asset = CanonicalCBOMAsset.model_validate(canonical_asset_json)
    doc = build_cyclonedx_document("scan_test_123", [asset])

    assert doc.bomFormat == "CycloneDX"
    assert doc.specVersion == "1.6"
    assert doc.version == 1
    assert len(doc.components) == 1
    assert doc.components[0].bom_ref == "crypto-asset-0af3e9"
