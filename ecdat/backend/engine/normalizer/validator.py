"""CycloneDX 1.6 CBOM and CONTRACT.md Document Validator.

Verifies generated CBOM documents against CycloneDX 1.6 cryptographic-asset specifications
and ECDAT CONTRACT.md Boundary 2 schema rules.
"""

from __future__ import annotations

import json
from typing import Any

from backend.models.schemas import CBOMAsset, CBOMDocument

REQUIRED_TOP_KEYS = {"bomFormat", "specVersion", "serialNumber", "version", "components"}
REQUIRED_ASSET_KEYS = {"bom-ref", "type", "name", "cryptoProperties", "occurrences", "ecdatEnrichment"}
REQUIRED_CRYPTO_PROPS_KEYS = {"assetType", "algorithmProperties"}
REQUIRED_ALGO_PROPS_KEYS = {
    "primitive",
    "parameterSetIdentifier",
    "executionEnvironment",
    "implementationPlatform",
    "cryptoFunctions",
    "classicalSecurityLevel",
    "nistQuantumSecurityLevel",
}
REQUIRED_ENRICHMENT_KEYS = {
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
ALLOWED_RISK_TIERS = {"Critical", "High", "Medium", "Low"}
ALLOWED_EXPOSURE = {"external-facing", "internal-only"}


class CBOMValidationError(ValueError):
    """Raised when a CBOM document or asset fails contract validation."""
    pass


def validate_cbom_asset(asset_dict: dict[str, Any]) -> list[str]:
    """Validate a single CBOM asset dictionary against CONTRACT.md specifications."""
    errors: list[str] = []

    # 1. Top-level asset keys
    for key in REQUIRED_ASSET_KEYS:
        if key not in asset_dict:
            errors.append(f"Missing required asset key: '{key}'")

    if asset_dict.get("type") != "cryptographic-asset":
        errors.append(f"Asset 'type' must be 'cryptographic-asset', got: '{asset_dict.get('type')}'")

    if not asset_dict.get("bom-ref"):
        errors.append("Asset 'bom-ref' cannot be empty")

    if not asset_dict.get("name"):
        errors.append("Asset 'name' cannot be empty")

    # 2. cryptoProperties block
    cp = asset_dict.get("cryptoProperties")
    if not isinstance(cp, dict):
        errors.append("Asset 'cryptoProperties' must be an object")
    else:
        for k in REQUIRED_CRYPTO_PROPS_KEYS:
            if k not in cp:
                errors.append(f"Missing required cryptoProperties key: '{k}'")

        ap = cp.get("algorithmProperties")
        if not isinstance(ap, dict):
            errors.append("cryptoProperties 'algorithmProperties' must be an object")
        else:
            for k in REQUIRED_ALGO_PROPS_KEYS:
                if k not in ap:
                    errors.append(f"Missing required algorithmProperties key: '{k}'")

    # 3. occurrences block
    occs = asset_dict.get("occurrences")
    if not isinstance(occs, list):
        errors.append("Asset 'occurrences' must be a list")
    else:
        for i, occ in enumerate(occs):
            if not isinstance(occ, dict) or "location" not in occ:
                errors.append(f"Occurrence #{i} must be an object with a 'location' key")

    # 4. ecdatEnrichment block
    enr = asset_dict.get("ecdatEnrichment")
    if not isinstance(enr, dict):
        errors.append("Asset 'ecdatEnrichment' must be an object")
    else:
        for k in REQUIRED_ENRICHMENT_KEYS:
            if k not in enr:
                errors.append(f"Missing required ecdatEnrichment key: '{k}'")

        tier = enr.get("moscaRiskTier")
        if tier not in ALLOWED_RISK_TIERS:
            errors.append(f"moscaRiskTier must be one of {ALLOWED_RISK_TIERS}, got: '{tier}'")

        if not isinstance(enr.get("quantumVulnerable"), bool):
            errors.append("ecdatEnrichment 'quantumVulnerable' must be a boolean")

        if not isinstance(enr.get("moscaR"), (int, float)):
            errors.append("ecdatEnrichment 'moscaR' must be a numeric value")

    return errors


def validate_cbom_document(doc: dict[str, Any] | CBOMDocument) -> list[str]:
    """Validate a complete CycloneDX 1.6 CBOM document against official contract rules.

    Returns a list of validation error strings. If empty, the document is 100% valid.
    """
    if isinstance(doc, CBOMDocument):
        doc_dict = json.loads(doc.model_dump_json(by_alias=True))
    else:
        doc_dict = doc

    errors: list[str] = []

    # 1. Document header
    for key in REQUIRED_TOP_KEYS:
        if key not in doc_dict:
            errors.append(f"Missing document key: '{key}'")

    if doc_dict.get("bomFormat") != "CycloneDX":
        errors.append(f"bomFormat must be 'CycloneDX', got: '{doc_dict.get('bomFormat')}'")

    if doc_dict.get("specVersion") != "1.6":
        errors.append(f"specVersion must be '1.6', got: '{doc_dict.get('specVersion')}'")

    serial = doc_dict.get("serialNumber", "")
    if not isinstance(serial, str) or not serial.startswith("urn:uuid:"):
        errors.append(f"serialNumber must be a URN starting with 'urn:uuid:', got: '{serial}'")

    # 2. Components list
    components = doc_dict.get("components")
    if not isinstance(components, list):
        errors.append("Document 'components' must be a list")
    else:
        for i, comp in enumerate(components):
            comp_errors = validate_cbom_asset(comp)
            for e in comp_errors:
                errors.append(f"Component #{i} ({comp.get('name', 'unknown')}): {e}")

    return errors


def assert_valid_cbom(doc: dict[str, Any] | CBOMDocument) -> None:
    """Validate CBOM document and raise CBOMValidationError if invalid."""
    errors = validate_cbom_document(doc)
    if errors:
        raise CBOMValidationError(f"CBOM Document validation failed with {len(errors)} error(s):\n" + "\n".join(errors))

