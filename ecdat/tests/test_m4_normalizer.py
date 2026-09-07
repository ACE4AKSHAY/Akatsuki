"""Unit tests for M4 CBOM Aggregation & Normalization Engine."""

import pytest
from backend.engine.normalizer import build_cbom_document, lookup_canonical, normalize, resolve_tagging
from backend.models.schemas import RawFinding


def test_canonical_algorithm_lookup():
    """Verify alias normalization against Section 8 seed."""
    # Hashes
    entry_sha1 = lookup_canonical("SHA1")
    assert entry_sha1 is not None
    assert entry_sha1.canonical_name == "SHA-1"
    assert entry_sha1.oid == "1.3.14.3.2.26"
    assert entry_sha1.quantum_class == "classically-broken"

    entry_sha1_dash = lookup_canonical("sha-1")
    assert entry_sha1_dash == entry_sha1

    entry_sha1_hashlib = lookup_canonical("hashlib.sha1")
    assert entry_sha1_hashlib == entry_sha1

    # Symmetric ciphers
    entry_aes = lookup_canonical("AES-128")
    assert entry_aes is not None
    assert entry_aes.canonical_name == "AES-128"
    assert entry_aes.oid == "2.16.840.1.101.3.4.1.2"

    entry_aes_cbc = lookup_canonical("aes-128-cbc")
    assert entry_aes_cbc == entry_aes

    # Asymmetric key exchange & signatures
    entry_rsa = lookup_canonical("RSA")
    assert entry_rsa is not None
    assert entry_rsa.primitive == "key-exchange"
    assert entry_rsa.quantum_class == "shor"

    entry_ecdsa = lookup_canonical("ECDSA")
    assert entry_ecdsa is not None
    assert entry_ecdsa.primitive == "signature"
    assert entry_ecdsa.quantum_class == "shor"


def test_deduplication_across_tiers_and_scanners():
    """Verify that findings sharing (algorithm, filePath, line) collapse into one asset."""
    findings = [
        # Scanner M1, tier regex
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId="scan_test",
            filePath="src/auth/token_signer.py",
            lineNumber=42,
            language="python",
            library="pyca/cryptography",
            rawSignal="hashes.SHA1()",
            detectedPrimitive="SHA1",
            primitiveCategory="hash",
            keySizeBits=None,
            mode=None,
            confidence=0.8,
            detectionTier="regex",
        ),
        # Scanner M1, tier AST (same location and primitive)
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId="scan_test",
            filePath="src/auth/token_signer.py",
            lineNumber=42,
            language="python",
            library="pyca/cryptography",
            rawSignal="hashes.SHA1()",
            detectedPrimitive="sha-1",
            primitiveCategory="hash",
            keySizeBits=None,
            mode=None,
            confidence=0.95,
            detectionTier="ast",
        ),
        # Scanner M1, tier AST (different line in same file)
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId="scan_test",
            filePath="src/auth/token_signer.py",
            lineNumber=85,
            language="python",
            library="pyca/cryptography",
            rawSignal="hashes.SHA1()",
            detectedPrimitive="SHA_1",
            primitiveCategory="hash",
            keySizeBits=None,
            mode=None,
            confidence=0.95,
            detectionTier="ast",
        ),
    ]

    assets = normalize(findings)
    assert len(assets) == 1, "Should collapse into single asset for this file & canonical algorithm"
    asset = assets[0]

    # Check deduplicated occurrences
    assert len(asset.occurrences) == 2
    lines = [occ.line for occ in asset.occurrences]
    assert sorted(lines) == [42, 85]
    assert asset.occurrences[0].location == "src/auth/token_signer.py"


def test_tagging_resolution():
    """Verify path-based metadata tagging."""
    auth_tags = resolve_tagging("src/auth/token_signer.py")
    assert auth_tags["businessCriticality"] == "High"
    assert auth_tags["dataClassification"] == "Authentication-Token"
    assert auth_tags["exposure"] == "external-facing"

    pii_tags = resolve_tagging("services/pii/customer_store.py")
    assert pii_tags["businessCriticality"] == "Critical"
    assert pii_tags["dataClassification"] == "PII"

    default_tags = resolve_tagging("lib/internal_helper.py")
    assert default_tags["businessCriticality"] == "Medium"
    assert default_tags["exposure"] == "internal-only"


def test_cyclonedx_document_builder():
    """Verify wrapping assets into CycloneDX 1.6 document container."""
    findings = [
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId="scan_test",
            filePath="src/crypto.py",
            lineNumber=10,
            language="python",
            library="cryptography",
            rawSignal="AES.new()",
            detectedPrimitive="AES-128",
            primitiveCategory="cipher",
            keySizeBits=128,
            mode="CBC",
            confidence=0.9,
            detectionTier="ast",
        )
    ]
    assets = normalize(findings)
    doc = build_cbom_document(assets, serial_number="urn:uuid:test-doc-123")

    assert doc.bomFormat == "CycloneDX"
    assert doc.specVersion == "1.6"
    assert doc.serialNumber == "urn:uuid:test-doc-123"
    assert doc.version == 1
    assert len(doc.components) == 1
    assert doc.components[0].name == "AES-128"


def test_cbom_validator():
    """Verify CycloneDX 1.6 and CONTRACT.md document validator."""
    from backend.engine.normalizer.validator import assert_valid_cbom, validate_cbom_document

    findings = [
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId="scan_test",
            filePath="src/auth/token_signer.py",
            lineNumber=42,
            language="python",
            library="pyca/cryptography",
            rawSignal="hashes.SHA1()",
            detectedPrimitive="SHA1",
            primitiveCategory="hash",
            keySizeBits=None,
            mode=None,
            confidence=0.95,
            detectionTier="ast",
        )
    ]
    assets = normalize(findings)
    doc = build_cbom_document(assets, serial_number="urn:uuid:valid-doc-123")

    errors = validate_cbom_document(doc)
    assert errors == [], f"Validation errors: {errors}"
    # Must not raise
    assert_valid_cbom(doc)
