"""PQC and Hybrid Cryptographic Recommendation Engine (M6).

Maps quantum-vulnerable and classically deprecated algorithms to concrete NIST
post-quantum standardized primitives (FIPS 203, FIPS 204, FIPS 205) and hybrid schemes,
with support for CNSA 2.0 mandates and latency-sensitive constraints.
"""

from __future__ import annotations

from typing import Any

from backend.engine.normalizer.canonical import lookup_canonical
from backend.engine.risk.risk_engine import is_classically_broken
from backend.models.schemas import CBOMAsset, ConstraintConfig


def recommend_for_asset(
    asset: CBOMAsset,
    constraints: ConstraintConfig | None = None,
) -> CBOMAsset:
    """Compute and attach PQC/hybrid recommendations to a canonical CBOM asset."""
    c = constraints or ConstraintConfig()
    enrichment = asset.ecdatEnrichment
    props = asset.cryptoProperties.algorithmProperties
    name = asset.name.strip()
    norm_name = name.lower().replace("_", "-").replace(" ", "")

    canon = lookup_canonical(name) or lookup_canonical(props.parameterSetIdentifier or "")
    canon_name = canon.canonical_name if canon else name
    prim = (props.primitive or "").lower()

    # Determine recommendation based on category & algorithm
    rec_replacement = ""
    ref_standard = ""
    rec_mode = "pure"
    complexity = "Medium"
    size_delta = ""
    rationale = ""

    # 1. Classically broken hashes
    if norm_name in {"md5", "sha1", "sha-1"}:
        rec_replacement = "SHA-384 or SHA3-384"
        ref_standard = "N/A (deprecate; not a PQC concern, a classical-strength concern)"
        rec_mode = "pure"
        complexity = "Low"
        size_delta = "digest size 48 bytes (vs 16/20 bytes)"
        rationale = "Classically broken (collision attacks); migrate to SHA-384 or SHA3-384 to maintain >=192-bit classical and >=128-bit Grover margin."

    # 2. Classically broken symmetric ciphers
    elif norm_name in {"des", "3des", "tripledes", "rc2", "rc4", "arcfour", "blowfish"}:
        rec_replacement = "AES-256-GCM or ChaCha20-Poly1305"
        ref_standard = "N/A (deprecate; not a PQC concern, a classical-strength concern)"
        rec_mode = "pure"
        complexity = "Medium"
        size_delta = "256-bit key, 128-bit authentication tag"
        rationale = "Classically deprecated and insecure. Replace immediately with modern AEAD authenticated encryption."

    # 3. Key Exchange (RSA, DH, ECDH, X25519, X448)
    elif prim in {"key-exchange", "key-agreement"} or norm_name in {
        "rsa", "dh", "diffiehellman", "ecdh", "x25519", "x448",
    }:
        if c.complianceTarget == "CNSA2.0":
            rec_replacement = "ML-KEM-1024"
            ref_standard = "NIST FIPS 203 / CNSA 2.0"
            rec_mode = "pure"
            complexity = "High"
            size_delta = "ciphertext 1,568 bytes, public key 1,568 bytes"
            rationale = "CNSA 2.0 mandates pure ML-KEM-1024 for national security systems by 2030-2033."
        elif c.latencySensitive:
            rec_replacement = "ML-KEM-512 or X25519MLKEM768"
            ref_standard = "NIST FIPS 203"
            rec_mode = "hybrid"
            complexity = "Medium"
            size_delta = "ciphertext 768 bytes, public key 800 bytes (minimized MTU fragmentation)"
            rationale = "Latency-sensitive context: compact parameter set minimizes network MTU overflow while establishing PQC defense."
        else:
            rec_replacement = "ML-KEM-768 (X25519MLKEM768 hybrid)"
            ref_standard = "NIST FIPS 203 (ML-KEM)"
            rec_mode = "hybrid"
            complexity = "Medium"
            size_delta = "ciphertext ~1,088 bytes (vs 256B RSA-2048), public key ~1,184 bytes (vs 256B RSA-2048)"
            rationale = "NIST FIPS 203 standard. Hybrid X25519MLKEM768 provides dual-layer classical and post-quantum security matching TLS 1.3 defaults."

    # 4. Digital Signatures (RSA-PSS, RSA, DSA, ECDSA, Ed25519, Ed448)
    elif prim in {"signature", "digital-signature"} or norm_name in {
        "rsa-pss", "dsa", "ecdsa", "ed25519", "ed448",
    }:
        is_firmware = (
            c.conservativeHighAssurance
            or "firmware" in (enrichment.dataClassification or "").lower()
            or "firmware" in (enrichment.vulnerabilityReason or "").lower()
        )
        if is_firmware:
            rec_replacement = "SLH-DSA (FIPS 205)"
            ref_standard = "NIST FIPS 205 (SLH-DSA)"
            rec_mode = "pure"
            complexity = "Medium"
            size_delta = "signature 7,856 - 17,088 bytes, public key 32 - 64 bytes"
            rationale = "High-assurance/firmware context: stateless hash-based signature (SLH-DSA) relies purely on hash collision resistance."
        elif c.complianceTarget == "CNSA2.0":
            rec_replacement = "ML-DSA-87"
            ref_standard = "NIST FIPS 204 / CNSA 2.0"
            rec_mode = "pure"
            complexity = "High"
            size_delta = "signature 4,595 bytes, public key 2,592 bytes"
            rationale = "CNSA 2.0 mandates pure ML-DSA-87 for digital signatures in national security environments."
        else:
            rec_replacement = "ML-DSA-65"
            ref_standard = "NIST FIPS 204 (ML-DSA)"
            rec_mode = "pure"
            complexity = "Medium"
            size_delta = "signature ~3,309 bytes (vs 256B RSA-2048), public key ~1,952 bytes (vs 256B RSA-2048)"
            rationale = "NIST FIPS 204 primary general-purpose post-quantum digital signature algorithm."

    # 5. Symmetric Ciphers (AES-128, AES-192)
    elif norm_name in {"aes-128", "aes128", "aes-192", "aes192"}:
        rec_replacement = "AES-256-GCM"
        ref_standard = "NIST FIPS 197 / SP 800-38D"
        rec_mode = "pure"
        complexity = "Low"
        size_delta = "256-bit key (doubles key schedule, zero ciphertext expansion)"
        rationale = "Restores full 128-bit security margin against Grover's quantum search algorithm."

    # 6. Grover-weakened Hash (SHA-224, SHA-256)
    elif norm_name in {"sha-224", "sha224", "sha-256", "sha256", "sha3-256", "sha3256"}:
        if c.complianceTarget == "CNSA2.0":
            rec_replacement = "SHA-384"
            ref_standard = "CNSA 2.0 / NIST FIPS 180-4"
            rec_mode = "pure"
            complexity = "Low"
            size_delta = "digest size 48 bytes (vs 32 bytes)"
            rationale = "CNSA 2.0 mandates SHA-384 or SHA-512 to preserve >=192 bits security margin against Grover search."
        else:
            rec_replacement = "SHA-384 or SHA3-384"
            ref_standard = "NIST FIPS 180-4 / FIPS 202"
            rec_mode = "pure"
            complexity = "Low"
            size_delta = "digest size 48 bytes (vs 32 bytes)"
            rationale = "Upgrade to SHA-384/SHA3-384 ensures full resistance against Grover's algorithm for long-retention data."

    # 7. Already quantum-safe / standardized PQC
    elif norm_name in {
        "aes-256", "aes256", "chacha20", "sha-384", "sha384", "sha-512", "sha512",
        "sha3-384", "sha3-512", "blake2b", "blake3", "ml-kem-512", "ml-kem-768",
        "ml-kem-1024", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa",
    }:
        rec_replacement = "Current algorithm meets PQC/classical standards"
        ref_standard = "NIST Post-Quantum Standards Compliant"
        rec_mode = "compliant"
        complexity = "None"
        size_delta = "No change required"
        rationale = "Asset already deploys quantum-resistant parameters or NIST-standardized PQC."

    # 8. Fallback
    else:
        rec_replacement = "Consult NIST SP 800-227 / FIPS 203-205 migration guide"
        ref_standard = "NIST Post-Quantum Migration Guidance"
        rec_mode = "hybrid"
        complexity = "Medium"
        size_delta = "dependent on primitive selection"
        rationale = "Evaluate protocol context and select FIPS 203 (KEM) or FIPS 204/205 (signature) substitute."

    # Write directly into ecdatEnrichment per CONTRACT.md
    enrichment.recommendedReplacement = rec_replacement
    enrichment.referenceStandard = ref_standard
    enrichment.recommendedMode = rec_mode
    enrichment.migrationComplexity = complexity
    enrichment.sizeDelta = size_delta
    enrichment.rationale = rationale

    return asset


def recommend(
    assets: list[CBOMAsset],
    constraints: ConstraintConfig | None = None,
) -> list[CBOMAsset]:
    """Apply PQC and hybrid recommendations across all canonical CBOM assets."""
    return [recommend_for_asset(a, constraints) for a in assets]
