"""
M5: Quantum Risk Assessment Engine
Implements Mosca's Algorithm: X + Y > Z
Urgency ratio r = (X + Y) / Z
Auto-escalation for classically broken algorithms, and composite risk scoring.
"""
from typing import Tuple, Dict, Any, Optional

CLASSICALLY_BROKEN_PRIMITIVES = {
    "MD5",
    "SHA1",
    "SHA-1",
    "DES",
    "3DES",
    "TRIPLEDES",
    "RC4",
    "RC2",
    "BLOWFISH",
}

SHOR_VULNERABLE_PRIMITIVES = {
    "RSA",
    "DSA",
    "DH",
    "DIFFIE-HELLMAN",
    "ECDH",
    "ECDSA",
    "EDDSA",
    "ED25519",
    "ED448",
    "X25519",
    "X448",
}

GROVER_WEAKENED_PRIMITIVES = {
    "AES-128",
    "AES128",
    "SHA-256",
    "SHA256",
    "SHA-224",
    "SHA224",
}

SAFE_OR_PQC_PRIMITIVES = {
    "AES-256",
    "AES256",
    "CHACHA20",
    "SHA-384",
    "SHA384",
    "SHA-512",
    "SHA512",
    "SHA3-384",
    "SHA3-512",
    "ML-KEM",
    "ML-KEM-768",
    "ML-KEM-1024",
    "ML-DSA",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA",
    "FIPS203",
    "FIPS204",
    "FIPS205",
}


def calculate_mosca_ratio(x: float, y: float, z: float) -> float:
    """Computes Mosca continuous urgency ratio r = (X + Y) / Z."""
    if z <= 0.0:
        return 999.0
    return round((x + y) / z, 4)


def get_mosca_tier(r: float) -> str:
    """
    Tier thresholds per Section 9.2:
    r >= 1.2 -> Critical
    0.9 <= r < 1.2 -> High
    0.6 <= r < 0.9 -> Medium
    r < 0.6 -> Low
    """
    if r >= 1.2:
        return "Critical"
    elif r >= 0.9:
        return "High"
    elif r >= 0.6:
        return "Medium"
    else:
        return "Low"


def compute_quantum_vulnerability_score(name: str, key_size: Optional[int] = None) -> float:
    """
    1.0: Shor's algorithm (asymmetric)
    0.6: Grover-weakened (AES-128, SHA-256)
    0.0: Safe or PQC
    """
    clean_name = name.upper().replace("_", "-").strip()

    # Check key size for AES or RSA
    if "AES" in clean_name and key_size:
        if key_size <= 128:
            return 0.6
        elif key_size >= 256:
            return 0.0

    for shor in SHOR_VULNERABLE_PRIMITIVES:
        if shor in clean_name:
            return 1.0

    for grover in GROVER_WEAKENED_PRIMITIVES:
        if grover in clean_name:
            return 0.6

    for safe in SAFE_OR_PQC_PRIMITIVES:
        if safe in clean_name:
            return 0.0

    # Default conservative
    return 0.6


def compute_composite_risk_score(
    quantum_vuln_score: float,
    r: float,
    business_criticality: str,
    exposure: str,
    weights: Optional[Dict[str, float]] = None,
) -> float:
    """
    Composite RiskScore per Section 9.3:
    RiskScore = w_q * QuantumVuln + w_r * normalize(r) + w_b * BusinessCrit + w_e * Exposure
    """
    w = weights or {
        "weight_quantum": 0.40,
        "weight_ratio": 0.25,
        "weight_business": 0.20,
        "weight_exposure": 0.15,
    }

    # normalize(r) capped at 1.0 (r=2.0 maps to 1.0)
    norm_r = min(max(r / 2.0, 0.0), 1.0)

    # Business Criticality Mapping
    crit_map = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}
    b_score = crit_map.get(business_criticality, 0.5)

    # Exposure Mapping
    e_score = 1.0 if "external" in exposure.lower() else 0.4

    score = (
        w.get("weight_quantum", 0.40) * quantum_vuln_score
        + w.get("weight_ratio", 0.25) * norm_r
        + w.get("weight_business", 0.20) * b_score
        + w.get("weight_exposure", 0.15) * e_score
    )
    return round(score, 4)


def evaluate_risk(
    name: str,
    x: float,
    y: float,
    z: float,
    business_criticality: str = "Medium",
    exposure: str = "internal-only",
    key_size: Optional[int] = None,
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Evaluates complete quantum risk, urgency ratio, auto-escalation, and composite score.
    """
    clean_name = name.upper().replace("_", "-").strip()
    r = calculate_mosca_ratio(x, y, z)
    calculated_tier = get_mosca_tier(r)

    # Check auto-escalation for classically broken algorithms
    is_classically_broken = any(broken in clean_name for broken in CLASSICALLY_BROKEN_PRIMITIVES)

    if is_classically_broken:
        final_tier = "Critical"
        auto_escalated = True
        reason = "classically broken (collision attacks); also loses Grover margin"
        quantum_vuln = True
        q_score = 1.0
    else:
        final_tier = calculated_tier
        auto_escalated = False
        q_score = compute_quantum_vulnerability_score(name, key_size)
        quantum_vuln = q_score > 0.0
        if q_score == 1.0:
            reason = "Vulnerable to Shor's algorithm on cryptographically-relevant quantum computers"
        elif q_score == 0.6:
            reason = "Effective security margin halved by Grover's algorithm"
        else:
            reason = "Quantum resistant under current known standards"

    risk_score = compute_composite_risk_score(
        q_score, r, business_criticality, exposure, weights
    )

    return {
        "x": x,
        "y": y,
        "z": z,
        "r": r,
        "calculatedTier": calculated_tier,
        "moscaRiskTier": final_tier,
        "autoEscalated": auto_escalated,
        "escalationReason": reason,
        "quantumVulnerable": quantum_vuln,
        "quantumVulnerabilityScore": q_score,
        "riskScore": risk_score,
    }
