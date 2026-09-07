"""Verification tests strictly validating compliance with CONTRACT.md.

Validates that emitted assets strictly adhere to Boundary 1 and Boundary 2 schemas
from CONTRACT.md.
"""

import json
from backend.models.schemas import (
    AlgorithmProperties,
    CBOMAsset,
    CryptoProperties,
    ECDATEnrichment,
    Occurrence,
    RawFinding,
)
from backend.orchestrator.pipeline import run_pipeline


def test_contract_boundary_1_raw_finding():
    """Verify Boundary 1 raw finding matches CONTRACT.md sample line 18-32."""
    raw_sample = {
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

    # Must validate cleanly into Pydantic model
    finding = RawFinding.model_validate(raw_sample)
    dumped = finding.model_dump()

    # Every single key from CONTRACT.md must be present
    for k in raw_sample:
        assert k in dumped


def test_contract_boundary_2_canonical_cbom_asset():
    """Verify Boundary 2 canonical CBOM asset matches CONTRACT.md sample line 48-83."""
    # Execute full pipeline for the exact CONTRACT.md finding
    raw_sample = {
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

    cbom_doc = run_pipeline(
        raw_findings=[raw_sample],
        scan_id="test_contract_scan",
    )

    assert len(cbom_doc.components) == 1
    asset = cbom_doc.components[0]
    asset_dict = json.loads(asset.model_dump_json(by_alias=True))

    # 1. Top-level CycloneDX keys
    expected_top_keys = {"bom-ref", "type", "name", "cryptoProperties", "occurrences", "ecdatEnrichment"}
    for k in expected_top_keys:
        assert k in asset_dict, f"Missing key '{k}' required by CONTRACT.md"

    assert asset_dict["type"] == "cryptographic-asset"
    assert asset_dict["name"] == "SHA1"

    # 2. cryptoProperties keys
    cp = asset_dict["cryptoProperties"]
    assert cp["assetType"] == "algorithm"
    assert "oid" in cp
    assert cp["oid"] == "1.3.14.3.2.26"

    ap = cp["algorithmProperties"]
    expected_ap_keys = {
        "primitive",
        "parameterSetIdentifier",
        "executionEnvironment",
        "implementationPlatform",
        "cryptoFunctions",
        "classicalSecurityLevel",
        "nistQuantumSecurityLevel",
    }
    for k in expected_ap_keys:
        assert k in ap, f"Missing algorithmProperties key '{k}' required by CONTRACT.md"

    # 3. Occurrences
    assert len(asset_dict["occurrences"]) == 1
    assert asset_dict["occurrences"][0]["location"] == "src/auth/token_signer.py"
    assert asset_dict["occurrences"][0]["line"] == 42

    # 4. ecdatEnrichment bag
    enr = asset_dict["ecdatEnrichment"]
    expected_enr_keys = {
        "quantumVulnerable",
        "vulnerabilityReason",
        "businessCriticality",
        "dataClassification",
        "exposure",
        "estimatedShelfLifeYears",
        "estimatedMigrationEffortYears",
        "moscaX",
        "moscaY",
        "moscaZ",
        "moscaR",
        "moscaRiskTier",
        "recommendedReplacement",
        "referenceStandard",
    }
    for k in expected_enr_keys:
        assert k in enr, f"Missing ecdatEnrichment key '{k}' required by CONTRACT.md"

    # CONTRACT.md Rule: moscaRiskTier must be one of "Critical" | "High" | "Medium" | "Low" (exact casing)
    assert enr["moscaRiskTier"] in {"Critical", "High", "Medium", "Low"}
    assert enr["moscaRiskTier"] == "Critical"
    assert "SHA-384" in enr["recommendedReplacement"]
    assert enr["referenceStandard"] == "N/A (deprecate; not a PQC concern, a classical-strength concern)"
    assert enr["vulnerabilityReason"] == "classically broken (collision attacks); also loses Grover margin"
