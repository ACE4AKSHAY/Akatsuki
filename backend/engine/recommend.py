"""
M6: PQC / Hybrid Recommendation Engine
Maps vulnerable cryptographic primitives to NIST FIPS 203/204/205 standards
and hybrid classical+PQC schemes.
"""
from typing import Dict, Any, Optional

def generate_recommendation(
    name: str,
    primitive_category: str,
    compliance_target: str = "NIST-general",
    latency_sensitive: bool = False,
    is_firmware: bool = False,
) -> Dict[str, Any]:
    """
    Generates migration recommendation based on Section 10 mapping table.
    """
    clean_name = name.upper().replace("_", "-").strip()
    is_cnsa2 = compliance_target == "CNSA2.0"

    # 1. Broken classical hashes
    if any(h in clean_name for h in ["MD5", "SHA1", "SHA-1"]):
        return {
            "recommendedReplacement": "SHA-384 or SHA3-384",
            "mode": "classical deprecation",
            "complexity": "Low",
            "rationale": "Classically broken (practical collision attacks); upgrade immediately to SHA-384+ or SHA3-384.",
            "referenceStandard": "N/A (deprecate; not a PQC concern, a classical-strength concern)",
            "relativeSizeDelta": "Comparable digest size (+128 bits)",
        }

    # 2. Broken classical symmetric
    if any(s in clean_name for s in ["DES", "3DES", "RC4", "RC2", "BLOWFISH"]):
        return {
            "recommendedReplacement": "AES-256-GCM or ChaCha20-Poly1305",
            "mode": "classical deprecation",
            "complexity": "Medium",
            "rationale": "Legacy cipher with severe cryptanalytic vulnerabilities; migrate to AES-256 in an AEAD mode.",
            "referenceStandard": "NIST SP 800-131A Rev 2",
            "relativeSizeDelta": "Standard block/stream overhead",
        }

    # 3. Grover-weakened symmetric: AES-128
    if "AES-128" in clean_name or clean_name == "AES128":
        return {
            "recommendedReplacement": "AES-256",
            "mode": "classical upgrade",
            "complexity": "Low",
            "rationale": "Grover's algorithm halves effective symmetric key length to 64-bit margin; bump to AES-256.",
            "referenceStandard": "NIST SP 800-131A Rev 2",
            "relativeSizeDelta": "Identical ciphertext size, +128 bit key size",
        }

    # 4. Asymmetric Digital Signatures
    is_signature = (
        primitive_category in ["asymmetric_sig", "signature", "cert"]
        or any(sig in clean_name for sig in ["SIGN", "ECDSA", "EDDSA", "ED25519", "DSA"])
    )

    if is_firmware:
        return {
            "recommendedReplacement": "SLH-DSA (FIPS 205)",
            "mode": "pure",
            "complexity": "High",
            "rationale": "Stateless hash-based signatures for high-assurance/firmware; relies only on hash-function security.",
            "referenceStandard": "FIPS 205",
            "relativeSizeDelta": "Signatures significantly larger (~7.8KB - 49KB)",
        }

    if is_signature:
        if is_cnsa2:
            return {
                "recommendedReplacement": "ML-DSA-87 (FIPS 204)",
                "mode": "pure",
                "complexity": "High",
                "rationale": "CNSA 2.0 mandate requires maximum security parameter set ML-DSA-87 for digital signatures.",
                "referenceStandard": "FIPS 204 / CNSA 2.0",
                "relativeSizeDelta": "Public key 2592 bytes, signature 4595 bytes",
            }
        else:
            rec = "ML-DSA-44" if latency_sensitive else "ML-DSA-65"
            return {
                "recommendedReplacement": f"{rec} (FIPS 204)",
                "mode": "hybrid or pure",
                "complexity": "Medium",
                "rationale": "NIST primary standard for general-purpose digital signatures based on module lattices.",
                "referenceStandard": "FIPS 204",
                "relativeSizeDelta": "Public key ~1952 bytes, signature ~3309 bytes (~4.7x larger than RSA-2048)",
            }

    # 5. Asymmetric Key Exchange / KEM (RSA, DH, ECDH, X25519)
    if is_cnsa2:
        return {
            "recommendedReplacement": "ML-KEM-1024 (FIPS 203)",
            "mode": "pure",
            "complexity": "High",
            "rationale": "CNSA 2.0 mandate requires highest security parameter set ML-KEM-1024 for key establishment.",
            "referenceStandard": "FIPS 203 / CNSA 2.0",
            "relativeSizeDelta": "Public key 1568 bytes, ciphertext 1568 bytes",
        }
    else:
        rec = "ML-KEM-512" if latency_sensitive else "ML-KEM-768"
        return {
            "recommendedReplacement": f"{rec} (FIPS 203)",
            "mode": "hybrid: X25519MLKEM768",
            "complexity": "Medium",
            "rationale": "FIPS 203 primary lattice-based KEM; recommended as hybrid X25519+ML-KEM-768 matching TLS 1.3 defaults.",
            "referenceStandard": "FIPS 203 / NIST SP 800-227",
            "relativeSizeDelta": "Public key 1184 bytes (~5.9x larger than RSA-2048), ciphertext 1088 bytes",
        }
