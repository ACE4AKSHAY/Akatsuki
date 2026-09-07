"""CBOM Aggregation and Normalization Engine (M4).

Transforms raw findings (Boundary 1) into deduplicated, CycloneDX 1.6-compliant
canonical CBOM assets (Boundary 2).
"""

from __future__ import annotations

import fnmatch
import hashlib
import uuid
from typing import Any

from backend.engine.normalizer.canonical import CanonicalEntry, lookup_canonical
from backend.models.schemas import (
    AlgorithmProperties,
    CBOMAsset,
    CBOMDocument,
    CryptoProperties,
    ECDATEnrichment,
    Occurrence,
    RawFinding,
)

# Default asset tagging configuration when no custom path rules match
DEFAULT_TAGGING: dict[str, Any] = {
    "businessCriticality": "Medium",
    "dataClassification": "Internal-Data",
    "exposure": "internal-only",
    "estimatedShelfLifeYears": 3.0,
    "estimatedMigrationEffortYears": 0.5,
}

# Standard patterns for path-based metadata inference
PATH_TAG_PATTERNS: list[tuple[str, dict[str, Any]]] = [
    (
        "*auth*",
        {
            "businessCriticality": "High",
            "dataClassification": "Authentication-Token",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 2.0,
            "estimatedMigrationEffortYears": 0.25,
        },
    ),
    (
        "*token*",
        {
            "businessCriticality": "High",
            "dataClassification": "Authentication-Token",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 2.0,
            "estimatedMigrationEffortYears": 0.25,
        },
    ),
    (
        "*pii*",
        {
            "businessCriticality": "Critical",
            "dataClassification": "PII",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 15.0,
            "estimatedMigrationEffortYears": 1.5,
        },
    ),
    (
        "*user*",
        {
            "businessCriticality": "High",
            "dataClassification": "Customer-PII",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 10.0,
            "estimatedMigrationEffortYears": 1.0,
        },
    ),
    (
        "*payment*",
        {
            "businessCriticality": "Critical",
            "dataClassification": "Financial",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 10.0,
            "estimatedMigrationEffortYears": 1.5,
        },
    ),
    (
        "*firmware*",
        {
            "businessCriticality": "Critical",
            "dataClassification": "Firmware-Signing",
            "exposure": "external-facing",
            "estimatedShelfLifeYears": 10.0,
            "estimatedMigrationEffortYears": 2.0,
        },
    ),
    (
        "*internal*",
        {
            "businessCriticality": "Medium",
            "dataClassification": "Internal-Data",
            "exposure": "internal-only",
            "estimatedShelfLifeYears": 3.0,
            "estimatedMigrationEffortYears": 0.5,
        },
    ),
]


def resolve_tagging(file_path: str, custom_config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Resolve business criticality, data classification, and exposure based on path glob rules."""
    norm_path = file_path.replace("\\", "/").lower()

    # Check user-provided custom config first
    if custom_config:
        for pattern, tags in custom_config.items():
            if fnmatch.fnmatch(norm_path, pattern.lower()) or fnmatch.fnmatch(file_path, pattern):
                merged = dict(DEFAULT_TAGGING)
                merged.update(tags)
                return merged

    # Check default heuristics
    for pattern, tags in PATH_TAG_PATTERNS:
        if fnmatch.fnmatch(norm_path, pattern):
            merged = dict(DEFAULT_TAGGING)
            merged.update(tags)
            return merged

    return dict(DEFAULT_TAGGING)


def _generate_bom_ref(canonical_name: str, location: str, line: int | None) -> str:
    """Generate deterministic, concise bom-ref identifier."""
    raw = f"{canonical_name}:{location}:{line}"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:6]
    return f"crypto-asset-{h}"


def normalize(
    findings: list[RawFinding | dict[str, Any]],
    tagging_config: dict[str, Any] | None = None,
) -> list[CBOMAsset]:
    """Normalize and deduplicate raw findings into canonical CBOM assets.

    Deduplication rule: Findings sharing identical (canonical_name, filePath, lineNumber)
    across tiers or scanners collapse into a single canonical asset with a unified occurrence list.
    """
    # Key: (canonical_name, filePath) -> dict with asset info and occurrences set
    grouped_assets: dict[tuple[str, str], dict[str, Any]] = {}

    for item in findings:
        finding = RawFinding.model_validate(item) if isinstance(item, dict) else item

        # Canonical lookup
        canon = lookup_canonical(finding.detectedPrimitive)
        if canon:
            canon_name = canon.canonical_name
            primitive = canon.primitive
            oid = canon.oid
            param_set_id = canon.parameter_set_identifier or canon.canonical_name
            crypto_funcs = list(canon.crypto_functions)
            sec_level = canon.classical_security_level
            nist_sec = canon.nist_quantum_security_level
            is_quantum_vuln = canon.quantum_vulnerable
            q_class = canon.quantum_class
        else:
            # Dynamic fallback
            canon_name = finding.detectedPrimitive
            primitive = finding.primitiveCategory
            oid = None
            param_set_id = finding.detectedPrimitive
            crypto_funcs = ["digest"] if finding.primitiveCategory == "hash" else ["encrypt"]
            sec_level = finding.keySizeBits or 128
            nist_sec = 0
            is_quantum_vuln = True
            q_class = "grover"

        group_key = (canon_name, finding.filePath)
        line = finding.lineNumber

        if group_key not in grouped_assets:
            tagging = resolve_tagging(finding.filePath, tagging_config)

            # Determine initial vulnerability reason
            if q_class == "classically-broken":
                vuln_reason = "classically broken (collision attacks); also loses Grover margin"
            elif q_class == "shor":
                vuln_reason = "broken by Shor's algorithm (polynomial time factor / discrete log)"
            elif q_class == "grover":
                vuln_reason = "halved security margin under Grover's algorithm"
            else:
                vuln_reason = "not vulnerable to known quantum attacks"

            grouped_assets[group_key] = {
                "name": finding.detectedPrimitive,
                "canon_name": canon_name,
                "primitive": primitive,
                "param_set_id": param_set_id,
                "crypto_funcs": crypto_funcs,
                "sec_level": sec_level,
                "nist_sec": nist_sec,
                "oid": oid,
                "occurrences_seen": set(),  # for deduplication of (location, line)
                "occurrences": [],
                "tagging": tagging,
                "quantum_vuln": is_quantum_vuln,
                "vuln_reason": vuln_reason,
            }

        # Deduplicate occurrence by (location, line)
        occ_tuple = (finding.filePath, line)
        if occ_tuple not in grouped_assets[group_key]["occurrences_seen"]:
            grouped_assets[group_key]["occurrences_seen"].add(occ_tuple)
            grouped_assets[group_key]["occurrences"].append(
                Occurrence(location=finding.filePath, line=line)
            )

    # Convert groups into canonical CBOMAsset objects
    canonical_assets: list[CBOMAsset] = []
    for (canon_name, file_path), data in grouped_assets.items():
        first_line = data["occurrences"][0].line if data["occurrences"] else None
        bom_ref = _generate_bom_ref(canon_name, file_path, first_line)

        tag = data["tagging"]
        x = float(tag.get("estimatedShelfLifeYears", 3.0))
        y = float(tag.get("estimatedMigrationEffortYears", 0.5))
        z = 8.0
        r = round((x + y) / z, 2)
        tier = "Critical" if r >= 1.2 else ("High" if r >= 0.9 else ("Medium" if r >= 0.6 else "Low"))

        enrichment = ECDATEnrichment(
            quantumVulnerable=data["quantum_vuln"],
            vulnerabilityReason=data["vuln_reason"],
            businessCriticality=tag.get("businessCriticality", "Medium"),
            dataClassification=tag.get("dataClassification", "Internal-Data"),
            exposure=tag.get("exposure", "internal-only"),
            estimatedShelfLifeYears=x,
            estimatedMigrationEffortYears=y,
            moscaX=x,
            moscaY=y,
            moscaZ=z,
            moscaR=r,
            moscaRiskTier=tier,
            recommendedReplacement="Pending M6 recommendation",
            referenceStandard="Pending M6 reference",
        )

        asset = CBOMAsset(
            bom_ref=bom_ref,
            type="cryptographic-asset",
            name=data["name"],
            cryptoProperties=CryptoProperties(
                assetType="algorithm",
                algorithmProperties=AlgorithmProperties(
                    primitive=data["primitive"],
                    parameterSetIdentifier=data["param_set_id"],
                    executionEnvironment="software-plain-ram",
                    implementationPlatform="generic",
                    cryptoFunctions=data["crypto_funcs"],
                    classicalSecurityLevel=data["sec_level"],
                    nistQuantumSecurityLevel=data["nist_sec"],
                ),
                oid=data["oid"],
            ),
            occurrences=data["occurrences"],
            ecdatEnrichment=enrichment,
        )
        canonical_assets.append(asset)

    return canonical_assets


def build_cbom_document(
    assets: list[CBOMAsset],
    serial_number: str | None = None,
) -> CBOMDocument:
    """Wrap canonical CBOM assets into a CycloneDX 1.6 document container."""
    doc_serial = serial_number or f"urn:uuid:{uuid.uuid4()}"
    return CBOMDocument(
        bomFormat="CycloneDX",
        specVersion="1.6",
        serialNumber=doc_serial,
        version=1,
        components=assets,
    )
