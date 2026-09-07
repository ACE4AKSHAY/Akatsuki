"""
M4: CBOM Aggregation & Normalization Engine
Deduplicates raw findings, canonicalizes algorithm names/OIDs,
enriches with business context, and builds CycloneDX 1.6 CBOM components.
"""
import uuid
from typing import List, Dict, Any, Optional
from backend.models.schemas import (
    RawFinding,
    CanonicalCBOMAsset,
    CryptoProperties,
    AlgorithmProperties,
    Occurrence,
    EcdatEnrichment,
    CycloneDXDocument,
)
from backend.engine.risk import evaluate_risk
from backend.engine.recommend import generate_recommendation

CANONICAL_ALGORITHM_MAP = {
    "SHA1": ("SHA-1", "1.3.14.3.2.26", "hash", ["digest"], 80, 0),
    "SHA-1": ("SHA-1", "1.3.14.3.2.26", "hash", ["digest"], 80, 0),
    "MD5": ("MD5", "1.2.840.113549.2.5", "hash", ["digest"], 64, 0),
    "SHA256": ("SHA-256", "2.16.840.1.101.3.4.2.1", "hash", ["digest"], 128, 1),
    "SHA-256": ("SHA-256", "2.16.840.1.101.3.4.2.1", "hash", ["digest"], 128, 1),
    "SHA384": ("SHA-384", "2.16.840.1.101.3.4.2.2", "hash", ["digest"], 192, 2),
    "SHA-384": ("SHA-384", "2.16.840.1.101.3.4.2.2", "hash", ["digest"], 192, 2),
    "SHA512": ("SHA-512", "2.16.840.1.101.3.4.2.3", "hash", ["digest"], 256, 3),
    "SHA-512": ("SHA-512", "2.16.840.1.101.3.4.2.3", "hash", ["digest"], 256, 3),
    "RSA": ("RSA", "1.2.840.113549.1.1.1", "asymmetric_kem", ["key-exchange", "signature"], 112, 0),
    "RSA-2048": ("RSA-2048", "1.2.840.113549.1.1.1", "asymmetric_kem", ["key-exchange", "signature"], 112, 0),
    "RSA-4096": ("RSA-4096", "1.2.840.113549.1.1.1", "asymmetric_kem", ["key-exchange", "signature"], 128, 0),
    "ECDSA": ("ECDSA", "1.2.840.10045.2.1", "asymmetric_sig", ["signature"], 128, 0),
    "ECDSA-P256": ("ECDSA-P256", "1.2.840.10045.3.1.7", "asymmetric_sig", ["signature"], 128, 0),
    "ECDH": ("ECDH", "1.3.132.1.12", "asymmetric_kem", ["key-exchange"], 128, 0),
    "X25519": ("X25519", "1.3.101.110", "asymmetric_kem", ["key-exchange"], 128, 0),
    "ED25519": ("Ed25519", "1.3.101.112", "asymmetric_sig", ["signature"], 128, 0),
    "AES-128": ("AES-128", "2.16.840.1.101.3.4.1.2", "symmetric", ["encrypt", "decrypt"], 128, 1),
    "AES-256": ("AES-256", "2.16.840.1.101.3.4.1.42", "symmetric", ["encrypt", "decrypt"], 256, 5),
    "DES": ("DES", "1.3.14.3.2.7", "symmetric", ["encrypt", "decrypt"], 56, 0),
    "3DES": ("3DES", "1.2.840.113549.3.7", "symmetric", ["encrypt", "decrypt"], 112, 0),
    "RC4": ("RC4", "1.2.840.113549.3.4", "symmetric", ["encrypt", "decrypt"], 40, 0),
}


def canonicalize_primitive(raw_name: str) -> tuple[str, Optional[str], str, list[str], int, int]:
    """Returns (canonical_name, oid, category, crypto_functions, classical_sec, nist_sec)."""
    norm = raw_name.upper().replace("_", "-").strip()
    if norm in CANONICAL_ALGORITHM_MAP:
        return CANONICAL_ALGORITHM_MAP[norm]
    # Fallback heuristic
    return (raw_name, None, "algorithm", ["encrypt", "decrypt"], 112, 0)


def infer_context_from_path(file_path: str, detected_primitive: str) -> tuple[str, str, str, float, float]:
    """
    Infers (business_criticality, data_classification, exposure, shelf_life_x, migration_effort_y).
    """
    path_lower = file_path.lower()
    clean_prim = detected_primitive.upper()

    # Classification & Shelf-Life (X)
    if any(k in path_lower for k in ["auth", "token", "session", "login"]):
        classification = "Authentication-Token"
        x = 2.0
        crit = "High"
    elif any(k in path_lower for k in ["pii", "user", "customer", "payment", "credit"]):
        classification = "Customer-PII"
        x = 15.0
        crit = "Critical"
    elif any(k in path_lower for k in ["firmware", "device", "boot", "rom"]):
        classification = "Firmware"
        x = 10.0
        crit = "Critical"
    elif any(k in path_lower for k in ["mtls", "internal", "service", "rpc"]):
        classification = "Internal-Operational"
        x = 3.0
        crit = "Medium"
    else:
        classification = "General"
        x = 5.0
        crit = "Medium"

    # Exposure
    if any(k in path_lower for k in ["auth", "api", "public", "gateway", "web", "external"]):
        exposure = "external-facing"
    else:
        exposure = "internal-only"

    # Migration Effort (Y)
    if any(k in clean_prim for k in ["RSA", "DH", "ECDH", "X25519"]):
        y = 1.5
    elif any(k in clean_prim for k in ["ECDSA", "ED25519", "DSA", "SIGN"]):
        y = 2.0
    elif any(k in clean_prim for k in ["SHA", "MD5"]):
        y = 0.25
    else:
        y = 0.5

    return crit, classification, exposure, x, y


def normalize_findings(
    findings: List[RawFinding],
    threat_timeline_z: float = 8.0,
    compliance_target: str = "NIST-general",
    weights: Optional[Dict[str, float]] = None,
) -> List[CanonicalCBOMAsset]:
    """
    Merges raw findings into deduplicated CanonicalCBOMAsset objects with ecdatEnrichment.
    """
    grouped_assets: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        can_name, oid, prim_cat, funcs, class_sec, nist_sec = canonicalize_primitive(f.detectedPrimitive)
        
        # Grouping key: by canonical algorithm and file path
        group_key = f"{can_name}::{f.filePath}"
        
        occ = Occurrence(location=f.filePath, line=f.lineNumber)

        if group_key not in grouped_assets:
            crit, classification, exposure, x, y = infer_context_from_path(f.filePath, can_name)

            # Check if this finding is specifically firmware
            is_firmware = classification == "Firmware"

            # Evaluate Risk (M5)
            risk_eval = evaluate_risk(
                name=can_name,
                x=x,
                y=y,
                z=threat_timeline_z,
                business_criticality=crit,
                exposure=exposure,
                key_size=f.keySizeBits,
                weights=weights,
            )

            # Generate Recommendation (M6)
            rec = generate_recommendation(
                name=can_name,
                primitive_category=f.primitiveCategory or prim_cat,
                compliance_target=compliance_target,
                is_firmware=is_firmware,
            )

            bom_ref = f"crypto-asset-{uuid.uuid4().hex[:6]}"

            enrichment = EcdatEnrichment(
                quantumVulnerable=risk_eval["quantumVulnerable"],
                vulnerabilityReason=risk_eval["escalationReason"],
                businessCriticality=crit,
                dataClassification=classification,
                exposure=exposure,
                estimatedShelfLifeYears=x,
                estimatedMigrationEffortYears=y,
                moscaX=x,
                moscaY=y,
                moscaZ=threat_timeline_z,
                moscaR=risk_eval["r"],
                moscaRiskTier=risk_eval["moscaRiskTier"],
                recommendedReplacement=rec["recommendedReplacement"],
                referenceStandard=rec["referenceStandard"],
                riskScore=risk_eval["riskScore"],
                autoEscalated=risk_eval["autoEscalated"],
                escalationReason=risk_eval["escalationReason"] if risk_eval["autoEscalated"] else None,
                recommendationMode=rec.get("mode"),
                migrationComplexity=rec.get("complexity"),
                relativeSizeDelta=rec.get("relativeSizeDelta"),
            )

            crypto_props = CryptoProperties(
                assetType="algorithm",
                algorithmProperties=AlgorithmProperties(
                    primitive=prim_cat,
                    parameterSetIdentifier=can_name,
                    executionEnvironment="software-plain-ram",
                    implementationPlatform="generic",
                    cryptoFunctions=funcs,
                    classicalSecurityLevel=class_sec,
                    nistQuantumSecurityLevel=nist_sec,
                ),
                oid=oid,
            )

            grouped_assets[group_key] = {
                "bom_ref": bom_ref,
                "name": can_name,
                "cryptoProperties": crypto_props,
                "occurrences": [occ],
                "ecdatEnrichment": enrichment,
            }
        else:
            # Deduplicate occurrence
            existing_locs = {(o.location, o.line) for o in grouped_assets[group_key]["occurrences"]}
            if (occ.location, occ.line) not in existing_locs:
                grouped_assets[group_key]["occurrences"].append(occ)

    # Build canonical assets list
    canonical_list = [
        CanonicalCBOMAsset(
            bom_ref=data["bom_ref"],
            name=data["name"],
            cryptoProperties=data["cryptoProperties"],
            occurrences=data["occurrences"],
            ecdatEnrichment=data["ecdatEnrichment"],
        )
        for data in grouped_assets.values()
    ]
    return canonical_list


def build_cyclonedx_document(scan_id: str, assets: List[CanonicalCBOMAsset]) -> CycloneDXDocument:
    """Wraps canonical assets into a CycloneDX 1.6 document."""
    return CycloneDXDocument(
        bomFormat="CycloneDX",
        specVersion="1.6",
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
        version=1,
        components=assets,
    )
