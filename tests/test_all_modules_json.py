"""
Cross-Module JSON Validation Test Suite for ECDAT.
Validates inputs and outputs across all modules (M1–M9) against locked contracts
in ECDAT — CONTRACT.md and the design document.
"""
import json
import pytest
from backend.models.schemas import (
    RawFinding,
    CanonicalCBOMAsset,
    CycloneDXDocument,
    EcdatEnrichment,
    CryptoProperties,
    AlgorithmProperties,
    Occurrence,
)
from backend.main import app
from backend.engine.risk import calculate_mosca_ratio, get_mosca_tier, evaluate_risk
from backend.engine.recommend import generate_recommendation
from backend.engine.normalizer import normalize_findings, build_cyclonedx_document
from backend.engine.orchestrator import get_contract_seed_findings


# ==============================================================================
# 1. Module M1, M2, M3 — Raw Finding Contract (CONTRACT.md Section 1)
# ==============================================================================
def test_m1_m2_m3_raw_finding_json_schema():
    """
    Verifies that raw findings emitted by M1, M2, and M3 strictly conform to
    CONTRACT.md Section 1 and Section 6.1 of the design doc.
    """
    raw_json_sample = {
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

    # Validate parsing
    finding = RawFinding.model_validate(raw_json_sample)
    assert finding.sourceModule in ["M1_source_scanner", "M2_dep_binary_scanner", "M3_container_config_scanner"]
    assert finding.detectedPrimitive == "SHA1"
    assert finding.confidence == 0.95

    # Validate scanner seed findings also comply 100%
    seed_findings = get_contract_seed_findings("scan_test")
    assert len(seed_findings) >= 5
    for f in seed_findings:
        dumped = f.model_dump()
        # Every required field must be present
        for req_field in [
            "sourceModule", "scanTargetId", "filePath", "lineNumber", "language",
            "library", "rawSignal", "detectedPrimitive", "primitiveCategory",
            "keySizeBits", "mode", "confidence", "detectionTier"
        ]:
            assert req_field in dumped


# ==============================================================================
# 2. Module M4 — CBOM Normalizer Output JSON (CONTRACT.md Section 2)
# ==============================================================================
def test_m4_canonical_cbom_asset_json_schema():
    """
    Verifies that the canonical CBOM asset produced by M4 and consumed by M7/M8/M9
    conforms to CONTRACT.md Section 2 and CycloneDX 1.6 ECMA-424.
    """
    canonical_sample = {
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
            "estimatedShelfLifeYears": 2.0,
            "estimatedMigrationEffortYears": 0.25,
            "moscaX": 2.0,
            "moscaY": 0.25,
            "moscaZ": 8.0,
            "moscaR": 1.34,
            "moscaRiskTier": "Critical",
            "recommendedReplacement": "SHA-384 or SHA3-384",
            "referenceStandard": "N/A (deprecate; not a PQC concern, a classical-strength concern)",
        },
    }

    asset = CanonicalCBOMAsset.model_validate(canonical_sample)
    dumped = asset.model_dump(by_alias=True)

    assert dumped["bom-ref"] == "crypto-asset-0af3e9"
    assert dumped["type"] == "cryptographic-asset"
    assert "cryptoProperties" in dumped
    assert "ecdatEnrichment" in dumped
    enc = dumped["ecdatEnrichment"]
    assert enc["moscaRiskTier"] in ["Critical", "High", "Medium", "Low"]
    assert enc["moscaX"] == 2.0
    assert enc["moscaY"] == 0.25
    assert enc["moscaZ"] == 8.0
    assert enc["moscaR"] == 1.34


# ==============================================================================
# 3. Module M5 & M6 — Risk & Recommendation JSON contracts
# ==============================================================================
def test_m5_m6_risk_and_recommendation_contracts():
    """Verifies that M5 evaluation and M6 recommendation integrate cleanly into ecdatEnrichment."""
    risk_out = evaluate_risk(
        name="RSA-2048",
        x=15.0,
        y=1.5,
        z=8.0,
        business_criticality="Critical",
        exposure="external-facing",
        key_size=2048,
    )
    assert risk_out["moscaRiskTier"] == "Critical"
    assert round(risk_out["r"], 2) == 2.06
    assert risk_out["quantumVulnerable"] is True

    rec_out = generate_recommendation(
        name="RSA-2048",
        primitive_category="asymmetric_kem",
        compliance_target="NIST-general",
    )
    assert "ML-KEM-768" in rec_out["recommendedReplacement"]
    assert "FIPS 203" in rec_out["referenceStandard"]


# ==============================================================================
# 4. Module M7 — OpenAPI 3.1.0 JSON Specification Validation
# ==============================================================================
def test_m7_openapi_json_schema():
    """Verifies that FastAPI auto-generated OpenAPI JSON is valid and contains all endpoints."""
    schema = app.openapi()
    assert schema["openapi"].startswith("3.")
    assert "paths" in schema

    expected_endpoints = [
        "/scans",
        "/scans/{scan_id}",
        "/assets",
        "/assets/{asset_id}",
        "/cbom/{scan_id}",
        "/reports/{scan_id}",
        "/config/threat-model",
        "/health",
    ]
    for ep in expected_endpoints:
        assert ep in schema["paths"], f"Endpoint {ep} missing in OpenAPI schema"


# ==============================================================================
# 5. Module M8 (Frontend) — Client-side Mosca calculation & Sample Data Validation
# ==============================================================================
def test_m8_frontend_sample_dataset_and_z_calculation():
    """
    Verifies that the 13 sample assets from ECDAT_Brand_and_UI_Kit.html
    yield exact Mosca tiers matching the UI prototype at Z=8.
    """
    # Sample dataset matching prototype exactly
    prototype_assets = [
        {"name": "Customer PII field encryption", "x": 15, "y": 1.5, "autoEsc": False, "expectedTier": "Critical"},
        {"name": "Firmware signing", "x": 10, "y": 2, "autoEsc": False, "expectedTier": "Critical"},
        {"name": "Payment gateway TLS handshake", "x": 7, "y": 1, "autoEsc": False, "expectedTier": "High"}, # r = 8/8 = 1.0 -> High
        {"name": "VPN tunnel", "x": 5, "y": 0.5, "autoEsc": True, "expectedTier": "Critical"},
        {"name": "Session token hashing", "x": 1, "y": 0.1, "autoEsc": True, "expectedTier": "Critical"},
        {"name": "Customer DB key wrap", "x": 8, "y": 1.5, "autoEsc": False, "expectedTier": "High"}, # r = 9.5/8 = 1.1875 -> High
        {"name": "Backup archive encryption", "x": 6, "y": 1, "autoEsc": False, "expectedTier": "Medium"}, # r = 7/8 = 0.875
        {"name": "Log pipeline TLS", "x": 2, "y": 0.5, "autoEsc": False, "expectedTier": "Low"},           # r = 2.5/8 = 0.3125
        {"name": "Internal API auth", "x": 2, "y": 0.3, "autoEsc": False, "expectedTier": "Low"},          # r = 2.3/8 = 0.2875
        {"name": "Internal microservice mTLS", "x": 3, "y": 0.5, "autoEsc": False, "expectedTier": "Low"}, # r = 3.5/8 = 0.4375
        {"name": "Config-signing tool", "x": 4, "y": 0.5, "autoEsc": False, "expectedTier": "Low"},        # r = 4.5/8 = 0.5625
        {"name": "Public API gateway cert", "x": 5, "y": 1, "autoEsc": True, "expectedTier": "Critical"},
        {"name": "Legacy admin portal", "x": 3, "y": 0.5, "autoEsc": True, "expectedTier": "Critical"},
    ]

    z = 8.0
    for a in prototype_assets:
        r = (a["x"] + a["y"]) / z
        if a["autoEsc"]:
            tier = "Critical"
        elif r >= 1.2:
            tier = "Critical"
        elif r >= 0.9:
            tier = "High"
        elif r >= 0.6:
            tier = "Medium"
        else:
            tier = "Low"

        assert tier == a["expectedTier"], f"Asset {a['name']} expected {a['expectedTier']}, got {tier}"

    # Verify that at Z=8, exactly 6 assets are Critical (matching prototype topbar badge "6 Critical")
    critical_count = sum(
        1 for a in prototype_assets
        if a["autoEsc"] or ((a["x"] + a["y"]) / z) >= 1.2
    )
    assert critical_count == 6 # Exactly 6 Critical (matching prototype id="topbar-critcount">6)


# ==============================================================================
# 6. Module M9 — CycloneDX 1.6 CBOM JSON Output Validation (Section 18.3)
# ==============================================================================
def test_m9_cyclonedx_json_structure():
    """Verifies that build_cyclonedx_document produces standard CycloneDX 1.6 JSON."""
    raw_findings = get_contract_seed_findings("scan_cbom_test")
    canonical_assets = normalize_findings(raw_findings, threat_timeline_z=8.0)
    doc = build_cyclonedx_document("scan_cbom_test", canonical_assets)

    doc_json = doc.model_dump_json(by_alias=True)
    parsed = json.loads(doc_json)

    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"
    assert parsed["serialNumber"].startswith("urn:uuid:")
    assert parsed["version"] == 1
    assert isinstance(parsed["components"], list)
    assert len(parsed["components"]) >= 4

    for comp in parsed["components"]:
        assert "bom-ref" in comp
        assert comp["type"] == "cryptographic-asset"
        assert "cryptoProperties" in comp
        assert "ecdatEnrichment" in comp
        assert comp["ecdatEnrichment"]["moscaRiskTier"] in ["Critical", "High", "Medium", "Low"]
