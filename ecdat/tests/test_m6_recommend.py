"""Unit tests for M6 PQC / Hybrid Recommendation Engine."""

import pytest
from backend.engine.normalizer import normalize
from backend.engine.recommend import recommend_for_asset
from backend.engine.risk import score_asset
from backend.models.schemas import ConstraintConfig, RawFinding


def _create_and_score(name: str, category: str, path: str = "src/crypto.py"):
    raw = RawFinding(
        sourceModule="M1_source_scanner",
        scanTargetId="scan_test",
        filePath=path,
        lineNumber=10,
        language="python",
        library="cryptography",
        rawSignal=f"crypto.{name}",
        detectedPrimitive=name,
        primitiveCategory=category,
        keySizeBits=None,
        mode=None,
        confidence=0.9,
        detectionTier="ast",
    )
    assets = normalize([raw])
    return score_asset(assets[0])


def test_key_exchange_recommendations():
    """Verify Section 10 mapping for Key Exchange primitives."""
    scored_rsa = _create_and_score("RSA", "key-exchange")

    # Default NIST-general -> ML-KEM-768 hybrid
    rec_default = recommend_for_asset(scored_rsa, ConstraintConfig(complianceTarget="NIST-general"))
    assert "ML-KEM-768" in rec_default.ecdatEnrichment.recommendedReplacement
    assert rec_default.ecdatEnrichment.recommendedMode == "hybrid"
    assert "FIPS 203" in rec_default.ecdatEnrichment.referenceStandard

    # CNSA 2.0 override -> ML-KEM-1024
    rec_cnsa = recommend_for_asset(scored_rsa, ConstraintConfig(complianceTarget="CNSA2.0"))
    assert "ML-KEM-1024" in rec_cnsa.ecdatEnrichment.recommendedReplacement
    assert rec_cnsa.ecdatEnrichment.recommendedMode == "pure"
    assert "CNSA 2.0" in rec_cnsa.ecdatEnrichment.referenceStandard

    # Latency sensitive -> ML-KEM-512 / compact hybrid
    rec_latency = recommend_for_asset(scored_rsa, ConstraintConfig(latencySensitive=True))
    assert "ML-KEM-512" in rec_latency.ecdatEnrichment.recommendedReplacement


def test_signature_recommendations():
    """Verify Section 10 mapping for Digital Signatures."""
    scored_ecdsa = _create_and_score("ECDSA", "signature")

    # Default NIST-general -> ML-DSA-65
    rec_sig = recommend_for_asset(scored_ecdsa, ConstraintConfig(complianceTarget="NIST-general"))
    assert "ML-DSA-65" in rec_sig.ecdatEnrichment.recommendedReplacement
    assert "FIPS 204" in rec_sig.ecdatEnrichment.referenceStandard

    # CNSA 2.0 override -> ML-DSA-87
    rec_cnsa_sig = recommend_for_asset(scored_ecdsa, ConstraintConfig(complianceTarget="CNSA2.0"))
    assert "ML-DSA-87" in rec_cnsa_sig.ecdatEnrichment.recommendedReplacement

    # High assurance / Firmware -> SLH-DSA
    scored_fw = _create_and_score("RSA-PSS", "signature", path="src/firmware/loader.py")
    rec_fw = recommend_for_asset(scored_fw, ConstraintConfig(conservativeHighAssurance=True))
    assert "SLH-DSA" in rec_fw.ecdatEnrichment.recommendedReplacement
    assert "FIPS 205" in rec_fw.ecdatEnrichment.referenceStandard


def test_symmetric_and_hash_recommendations():
    """Verify AES-128 and SHA-1 recommendations."""
    scored_aes128 = _create_and_score("AES-128", "cipher")
    rec_aes = recommend_for_asset(scored_aes128)
    assert "AES-256" in rec_aes.ecdatEnrichment.recommendedReplacement

    scored_sha1 = _create_and_score("SHA1", "hash")
    rec_sha1 = recommend_for_asset(scored_sha1)
    assert "SHA-384 or SHA3-384" in rec_sha1.ecdatEnrichment.recommendedReplacement


def test_already_safe_primitive():
    """Verify that already quantum-safe primitives require no changes."""
    scored_aes256 = _create_and_score("AES-256", "cipher")
    rec_aes256 = recommend_for_asset(scored_aes256)
    assert "meets PQC" in rec_aes256.ecdatEnrichment.recommendedReplacement
    assert rec_aes256.ecdatEnrichment.migrationComplexity == "None"
