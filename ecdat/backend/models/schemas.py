"""Pydantic schemas strictly enforcing CONTRACT.md data shapes.

Boundary 1: Raw finding (A -> B contract emitted by M1, M2, M3)
Boundary 2: Canonical CBOM asset (B -> C contract produced by M4, M5, M6, consumed by M7, M8, M9)
"""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Boundary 1: Raw Finding (A -> B)
# ---------------------------------------------------------------------------

class RawFinding(BaseModel):
    """Raw finding emitted by M1 (source), M2 (deps/binary), or M3 (infra/config).

    CONTRACT.md Rule: Every finding must have every field present.
    Use null (None) for fields that don't apply.
    """
    sourceModule: Literal[
        "M1_source_scanner",
        "M2_dep_binary_scanner",
        "M3_container_config_scanner",
    ] | str
    scanTargetId: str
    filePath: str
    lineNumber: int | None = None
    language: str | None = None
    library: str | None = None
    rawSignal: str
    detectedPrimitive: str
    primitiveCategory: str
    keySizeBits: int | None = None
    mode: str | None = None
    confidence: float = 1.0
    detectionTier: str


# ---------------------------------------------------------------------------
# Boundary 2: Canonical CBOM Asset (B -> C)
# ---------------------------------------------------------------------------

class Occurrence(BaseModel):
    """Occurrence of a cryptographic asset at a specific source location."""
    location: str
    line: int | None = None


class AlgorithmProperties(BaseModel):
    """CycloneDX 1.6 algorithmProperties block."""
    primitive: str
    parameterSetIdentifier: str | None = None
    executionEnvironment: str = "software-plain-ram"
    implementationPlatform: str = "generic"
    cryptoFunctions: list[str] = Field(default_factory=list)
    classicalSecurityLevel: int | None = None
    nistQuantumSecurityLevel: int | None = None


class CryptoProperties(BaseModel):
    """CycloneDX 1.6 cryptoProperties block."""
    assetType: str = "algorithm"
    algorithmProperties: AlgorithmProperties
    oid: str | None = None


class ECDATEnrichment(BaseModel):
    """ECDAT custom enrichment bag.

    CONTRACT.md Rule: M5 must write moscaX, moscaY, moscaZ, moscaR, moscaRiskTier.
    M6 must write recommendedReplacement and referenceStandard.
    moscaRiskTier must be one of "Critical" | "High" | "Medium" | "Low".
    """
    model_config = ConfigDict(extra="allow")

    quantumVulnerable: bool
    vulnerabilityReason: str
    businessCriticality: Literal["Critical", "High", "Medium", "Low"] | str
    dataClassification: str
    exposure: Literal["external-facing", "internal-only"] | str
    estimatedShelfLifeYears: float
    estimatedMigrationEffortYears: float
    moscaX: float
    moscaY: float
    moscaZ: float
    moscaR: float
    moscaRiskTier: Literal["Critical", "High", "Medium", "Low"] | str
    recommendedReplacement: str
    referenceStandard: str

    # Supplementary enrichment fields for M7 / M8 / M9
    riskScore: float | None = None
    autoEscalated: bool | None = None
    escalationReason: str | None = None
    recommendedMode: str | None = None
    migrationComplexity: str | None = None
    sizeDelta: str | None = None
    rationale: str | None = None


class CBOMAsset(BaseModel):
    """Canonical CBOM asset emitted by B (M4/M5/M6) and stored by M7.

    Complies with CycloneDX 1.6 cryptographic-asset specification.
    """
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    bom_ref: str = Field(..., alias="bom-ref")
    type: str = "cryptographic-asset"
    name: str
    cryptoProperties: CryptoProperties
    occurrences: list[Occurrence] = Field(default_factory=list)
    ecdatEnrichment: ECDATEnrichment


class CBOMDocument(BaseModel):
    """CycloneDX 1.6 top-level BOM container."""
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    bomFormat: str = "CycloneDX"
    specVersion: str = "1.6"
    serialNumber: str
    version: int = 1
    components: list[CBOMAsset] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Configuration & Control Models
# ---------------------------------------------------------------------------

class ThreatModelConfig(BaseModel):
    """Threat model configuration for M5 Mosca calculations."""
    threatTimelineYears: float = 8.0  # Z (years to CRQC)
    defaultShelfLifeByDataClassification: dict[str, float] = Field(
        default_factory=lambda: {
            "PII": 15.0,
            "Customer-PII": 15.0,
            "Healthcare": 25.0,
            "Financial": 10.0,
            "Authentication-Token": 2.0,
            "Session": 1.0,
            "Internal-Data": 5.0,
            "Public": 0.5,
        }
    )
    defaultMigrationTimeByAssetType: dict[str, float] = Field(
        default_factory=lambda: {
            "key-exchange": 1.5,
            "signature": 2.0,
            "certificate": 0.5,
            "cipher": 1.0,
            "hash": 0.25,
            "mac": 0.5,
            "kdf": 0.5,
            "protocol": 1.0,
        }
    )


class RiskWeights(BaseModel):
    """Tunable weights for composite RiskScore calculation (Section 9.3)."""
    quantum_vulnerability: float = 0.40
    urgency_ratio: float = 0.25
    business_criticality: float = 0.20
    exposure: float = 0.15


class ConstraintConfig(BaseModel):
    """Constraints passed to M6 Recommendation Engine."""
    complianceTarget: Literal["NIST-general", "CNSA2.0"] = "NIST-general"
    latencySensitive: bool = False
    conservativeHighAssurance: bool = False
