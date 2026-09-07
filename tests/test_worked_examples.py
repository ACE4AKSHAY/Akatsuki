"""
Unit tests reproducing the exact Worked Examples table from Section 9.4 of the design doc.
Validates Mosca inequality r = (X+Y)/Z, auto-escalation, and risk tier assignments.
"""
import pytest
from backend.engine.risk import evaluate_risk, calculate_mosca_ratio, get_mosca_tier


def test_section_9_4_customer_pii_rsa_key_exchange():
    """
    Asset: Customer PII field encryption
    Algorithm: RSA-2048 key exchange
    X = 15 yrs, Y = 1.5 yrs, Z = 8 yrs
    r = (15 + 1.5) / 8 = 2.06
    Tier: Critical
    """
    x, y, z = 15.0, 1.5, 8.0
    r = calculate_mosca_ratio(x, y, z)
    assert round(r, 2) == 2.06
    assert get_mosca_tier(r) == "Critical"

    eval_result = evaluate_risk(
        name="RSA-2048",
        x=x,
        y=y,
        z=z,
        business_criticality="Critical",
        exposure="internal-only",
        key_size=2048,
    )
    assert eval_result["moscaRiskTier"] == "Critical"
    assert eval_result["quantumVulnerable"] is True
    assert eval_result["autoEscalated"] is False


def test_section_9_4_internal_microservice_ecdsa_cert():
    """
    Asset: Internal microservice mTLS
    Algorithm: ECDSA-P256 cert
    X = 3 yrs, Y = 0.5 yrs, Z = 8 yrs
    r = (3 + 0.5) / 8 = 0.44
    Tier: Low
    """
    x, y, z = 3.0, 0.5, 8.0
    r = calculate_mosca_ratio(x, y, z)
    assert round(r, 2) == 0.44
    assert get_mosca_tier(r) == "Low"

    eval_result = evaluate_risk(
        name="ECDSA-P256",
        x=x,
        y=y,
        z=z,
        business_criticality="Medium",
        exposure="internal-only",
        key_size=256,
    )
    assert eval_result["moscaRiskTier"] == "Low"
    assert eval_result["quantumVulnerable"] is True
    assert eval_result["autoEscalated"] is False


def test_section_9_4_firmware_signing_rsa_2048():
    """
    Asset: Firmware signing
    Algorithm: RSA-2048 signature
    X = 10 yrs, Y = 2 yrs, Z = 8 yrs
    r = (10 + 2) / 8 = 1.5
    Tier: Critical
    """
    x, y, z = 10.0, 2.0, 8.0
    r = calculate_mosca_ratio(x, y, z)
    assert round(r, 2) == 1.50
    assert get_mosca_tier(r) == "Critical"

    eval_result = evaluate_risk(
        name="RSA-2048",
        x=x,
        y=y,
        z=z,
        business_criticality="Critical",
        exposure="internal-only",
        key_size=2048,
    )
    assert eval_result["moscaRiskTier"] == "Critical"
    assert eval_result["quantumVulnerable"] is True


def test_section_9_4_session_token_sha1_auto_escalation():
    """
    Asset: Session token hashing
    Algorithm: SHA-1
    Expected: Auto-escalated to Critical (classically broken) regardless of r
    """
    # Even with short shelf life and low migration time where r would be small:
    x, y, z = 0.1, 0.1, 8.0
    r = calculate_mosca_ratio(x, y, z)
    # Natural r is 0.025 (Low tier)
    assert get_mosca_tier(r) == "Low"

    # But evaluate_risk must auto-escalate it to Critical!
    eval_result = evaluate_risk(
        name="SHA-1",
        x=x,
        y=y,
        z=z,
        business_criticality="High",
        exposure="external-facing",
    )
    assert eval_result["moscaRiskTier"] == "Critical"
    assert eval_result["autoEscalated"] is True
    assert "classically broken" in eval_result["escalationReason"]
