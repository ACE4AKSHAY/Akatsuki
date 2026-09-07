"""Quantum Risk Assessment Engine (M5).

Implements Mosca's inequality (r = (X + Y) / Z), auto-escalation for
classically broken primitives, and composite risk scoring incorporating
quantum vulnerability, business criticality, and exposure.
"""

from __future__ import annotations

from typing import Any

from backend.engine.normalizer.canonical import lookup_canonical
from backend.models.schemas import (
    CBOMAsset,
    RiskWeights,
    ThreatModelConfig,
)

# Classically broken algorithms unconditionally escalated to Critical
CLASSICALLY_BROKEN_NAMES: set[str] = {
    "md5",
    "sha1",
    "sha-1",
    "des",
    "3des",
    "tripledes",
    "rc2",
    "rc4",
    "arcfour",
    "blowfish",
}

# Shor-broken primitives (polynomial time break on CRQC)
SHOR_VULNERABLE_PRIMITIVES: set[str] = {
    "rsa",
    "rsa-2048",
    "rsa-1024",
    "rsa-4096",
    "rsa-pss",
    "dh",
    "diffiehellman",
    "ecdh",
    "ecdh-p256",
    "ecdh-p384",
    "ecdh-p521",
    "dsa",
    "ecdsa",
    "ecdsa-p256",
    "ecdsa-p384",
    "ed25519",
    "ed448",
    "x25519",
    "x448",
}

# Grover-weakened symmetric/hash primitives
GROVER_WEAKENED_NAMES: set[str] = {
    "aes-128",
    "aes128",
    "aes-192",
    "aes192",
    "sha-224",
    "sha224",
    "sha-256",
    "sha256",
    "sha3-256",
    "sha3256",
}


def is_classically_broken(name: str, canonical_name: str | None = None) -> bool:
    """Check if an algorithm is classically broken."""
    n = name.strip().lower().replace("_", "-")
    if n in CLASSICALLY_BROKEN_NAMES or n.replace("-", "") in CLASSICALLY_BROKEN_NAMES:
        return True
    if canonical_name:
        cn = canonical_name.strip().lower().replace("_", "-")
        if cn in CLASSICALLY_BROKEN_NAMES or cn.replace("-", "") in CLASSICALLY_BROKEN_NAMES:
            return True
    return False


def get_quantum_vulnerability_score(
    name: str,
    primitive_category: str,
    quantum_class: str | None = None,
) -> tuple[float, bool, str]:
    """Calculate QuantumVulnerabilityScore (Section 9.3).

    Returns (score: 0.0 | 0.6 | 1.0, is_vulnerable: bool, reason: str)
    """
    n = name.strip().lower().replace("_", "-")
    clean = n.replace("-", "")

    # Classically broken primitives
    if is_classically_broken(name):
        return (
            1.0,
            True,
            "classically broken (collision attacks); also loses Grover margin",
        )

    # Shor's broken (asymmetric)
    if (
        primitive_category in {"key-exchange", "signature"}
        or n in SHOR_VULNERABLE_PRIMITIVES
        or clean in SHOR_VULNERABLE_PRIMITIVES
        or quantum_class == "shor"
    ):
        return (
            1.0,
            True,
            "broken by Shor's algorithm (asymmetric / discrete log / integer factorization)",
        )

    # Grover-weakened
    if n in GROVER_WEAKENED_NAMES or clean in GROVER_WEAKENED_NAMES or quantum_class == "grover":
        return (
            0.6,
            True,
            "effective security halved under Grover's quantum search algorithm",
        )

    # Safe / PQC
    return (
        0.0,
        False,
        "recommended quantum-resistant parameter set or NIST PQC standardized algorithm",
    )


def score_asset(
    asset: CBOMAsset,
    threat_model: ThreatModelConfig | None = None,
    weights: RiskWeights | None = None,
) -> CBOMAsset:
    """Score a single canonical CBOM asset using Mosca's model and composite weighting."""
    tm = threat_model or ThreatModelConfig()
    w = weights or RiskWeights()

    enrichment = asset.ecdatEnrichment
    props = asset.cryptoProperties.algorithmProperties
    canon = lookup_canonical(asset.name) or lookup_canonical(props.parameterSetIdentifier or "")
    canon_name = canon.canonical_name if canon else asset.name
    q_class = canon.quantum_class if canon else None

    # Determine X (Security Shelf-Life)
    x = enrichment.estimatedShelfLifeYears
    if x is None or x <= 0:
        data_class = enrichment.dataClassification
        x = tm.defaultShelfLifeByDataClassification.get(data_class, 3.0)

    # Determine Y (Migration Effort)
    y = enrichment.estimatedMigrationEffortYears
    if y is None or y <= 0:
        prim = props.primitive or "cipher"
        y = tm.defaultMigrationTimeByAssetType.get(prim, 0.5)

    # Determine Z (Threat Timeline)
    z = tm.threatTimelineYears if tm.threatTimelineYears > 0 else 8.0

    # Compute Mosca continuous ratio r = (X + Y) / Z
    r = round((x + y) / z, 2)

    # Classically broken check
    classically_broken = is_classically_broken(asset.name, canon_name)

    # Determine Mosca Risk Tier
    if classically_broken:
        tier = "Critical"
        auto_escalated = True
        escalation_reason = "classically broken, independent of quantum timeline"
        vuln_reason = "classically broken (collision attacks); also loses Grover margin"
    else:
        auto_escalated = False
        escalation_reason = None
        if r >= 1.2:
            tier = "Critical"
        elif r >= 0.9:
            tier = "High"
        elif r >= 0.6:
            tier = "Medium"
        else:
            tier = "Low"

    # Composite Risk Score Calculation
    qvs, is_vuln, reason_calc = get_quantum_vulnerability_score(asset.name, props.primitive, q_class)
    if not classically_broken:
        vuln_reason = reason_calc

    # normalize(r): scale 0.0 -> 1.5 ratio into 0.0 -> 1.0 range
    norm_r = min(max(r, 0.0) / 1.5, 1.0)

    # Business Criticality score
    bc_str = (enrichment.businessCriticality or "Medium").capitalize()
    if bc_str == "Critical":
        bcs = 1.0
    elif bc_str == "High":
        bcs = 0.75
    elif bc_str == "Low":
        bcs = 0.25
    else:
        bcs = 0.50

    # Exposure score
    exp_str = (enrichment.exposure or "internal-only").lower()
    if "external" in exp_str:
        es = 1.0
    else:
        es = 0.40

    # Composite formula (Section 9.3)
    composite = (
        w.quantum_vulnerability * qvs
        + w.urgency_ratio * norm_r
        + w.business_criticality * bcs
        + w.exposure * es
    )
    final_score = round(composite, 2)

    # Update enrichment with all Mosca and risk parameters
    enrichment.quantumVulnerable = is_vuln or classically_broken
    enrichment.vulnerabilityReason = vuln_reason
    enrichment.estimatedShelfLifeYears = x
    enrichment.estimatedMigrationEffortYears = y
    enrichment.moscaX = x
    enrichment.moscaY = y
    enrichment.moscaZ = z
    enrichment.moscaR = r
    enrichment.moscaRiskTier = tier
    enrichment.riskScore = final_score
    enrichment.autoEscalated = auto_escalated
    enrichment.escalationReason = escalation_reason

    return asset


def score_assets(
    assets: list[CBOMAsset],
    threat_model: ThreatModelConfig | None = None,
    weights: RiskWeights | None = None,
) -> list[CBOMAsset]:
    """Score a list of canonical CBOM assets."""
    return [score_asset(a, threat_model, weights) for a in assets]
