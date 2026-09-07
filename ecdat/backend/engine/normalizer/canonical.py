"""Canonical cryptographic algorithm lookup table for M4 (normalizer).

Every raw finding's `detectedPrimitive` is normalised against this table so
that e.g. "SHA1", "sha-1" and "SHA_1" all collapse onto one
canonical "SHA-1" entry carrying a well-known OID.

Seeded for every algorithm family listed in Section 8 of the design doc.
OIDs are the well-known ASN.1 / NIST / IANA identifiers where one exists;
PQC primitives have no widely deployed OID yet, so their `oid` is None.

Quantum classification mirrors Section 8:
  - shor                -> broken by Shor's (asymmetric)
  - grover              -> only Grover-weakened (symmetric / hash)
  - classically-broken  -> already broken today, independent of quantum
  - none                -> already at recommended strength, or PQC
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CanonicalEntry:
    """One canonical algorithm entry produced by M4."""

    canonical_name: str
    oid: str | None
    primitive: str
    quantum_class: str
    quantum_vulnerable: bool
    classical_security_level: int | None
    nist_quantum_security_level: int | None
    crypto_functions: list[str] = field(default_factory=list)
    parameter_set_identifier: str | None = None
    aliases: tuple[str, ...] = ()


def _norm_alias(name: str) -> str:
    """Lowercase and strip separators for fuzzy alias matching."""
    return re.sub(r"[\s\-_/]", "", name).lower()


# ---------------------------------------------------------------------------
# Canonical registry (Section 8 seed).
# ---------------------------------------------------------------------------
_CANONICAL: list[CanonicalEntry] = [
    # ---- Hashes -----------------------------------------------------------
    CanonicalEntry(
        "MD5", "1.2.840.113549.2.5", "hash", "classically-broken", True,
        128, 0, ["digest"], "MD5", ("MD5", "md5", "hashlib.md5"),
    ),
    CanonicalEntry(
        "SHA-1", "1.3.14.3.2.26", "hash", "classically-broken", True,
        80, 0, ["digest"], "SHA-1", ("SHA1", "SHA-1", "sha-1", "sha_1", "hashlib.sha1"),
    ),
    CanonicalEntry(
        "SHA-224", "2.16.840.1.101.3.4.2.4", "hash", "grover", True,
        112, 0, ["digest"], "SHA-224", ("SHA224", "SHA-224", "sha224", "sha-224"),
    ),
    CanonicalEntry(
        "SHA-256", "2.16.840.1.101.3.4.2.1", "hash", "grover", True,
        128, 0, ["digest"], "SHA-256", ("SHA256", "SHA-256", "sha256", "sha-256", "hashlib.sha256"),
    ),
    CanonicalEntry(
        "SHA-384", "2.16.840.1.101.3.4.2.2", "hash", "none", False,
        192, 0, ["digest"], "SHA-384", ("SHA384", "SHA-384", "sha384", "sha-384", "hashlib.sha384"),
    ),
    CanonicalEntry(
        "SHA-512", "2.16.840.1.101.3.4.2.3", "hash", "none", False,
        256, 0, ["digest"], "SHA-512", ("SHA512", "SHA-512", "sha512", "sha-512", "hashlib.sha512"),
    ),
    CanonicalEntry(
        "SHA3-256", "2.16.840.1.101.3.4.2.8", "hash", "grover", True,
        128, 0, ["digest"], "SHA3-256", ("SHA3-256", "SHA3256", "sha3-256", "sha3_256"),
    ),
    CanonicalEntry(
        "SHA3-384", "2.16.840.1.101.3.4.2.9", "hash", "none", False,
        192, 0, ["digest"], "SHA3-384", ("SHA3-384", "SHA3384", "sha3-384", "sha3_384"),
    ),
    CanonicalEntry(
        "SHA3-512", "2.16.840.1.101.3.4.2.10", "hash", "none", False,
        256, 0, ["digest"], "SHA3-512", ("SHA3-512", "SHA3512", "sha3-512", "sha3_512"),
    ),
    CanonicalEntry(
        "BLAKE2b", None, "hash", "none", False,
        256, 0, ["digest"], "BLAKE2b", ("BLAKE2b", "BLAKE2", "blake2b", "blake2"),
    ),
    CanonicalEntry(
        "BLAKE3", None, "hash", "none", False,
        256, 0, ["digest"], "BLAKE3", ("BLAKE3", "blake3"),
    ),

    # ---- Symmetric ciphers -------------------------------------------------
    CanonicalEntry(
        "AES-128", "2.16.840.1.101.3.4.1.2", "cipher", "grover", True,
        128, 0, ["encrypt", "decrypt"], "AES-128", ("AES-128", "AES128", "AES", "aes128", "aes-128-cbc", "aes-128-gcm"),
    ),
    CanonicalEntry(
        "AES-192", "2.16.840.1.101.3.4.1.22", "cipher", "grover", True,
        192, 0, ["encrypt", "decrypt"], "AES-192", ("AES-192", "AES192", "aes192", "aes-192-cbc", "aes-192-gcm"),
    ),
    CanonicalEntry(
        "AES-256", "2.16.840.1.101.3.4.1.42", "cipher", "none", False,
        256, 0, ["encrypt", "decrypt"], "AES-256", ("AES-256", "AES256", "aes256", "aes-256-cbc", "aes-256-gcm"),
    ),
    CanonicalEntry(
        "ChaCha20", None, "cipher", "none", False,
        256, 0, ["encrypt", "decrypt"], "ChaCha20", ("ChaCha20", "CHACHA20", "chacha20", "chacha20-poly1305"),
    ),
    CanonicalEntry(
        "DES", "1.3.14.3.2.7", "cipher", "classically-broken", True,
        56, 0, ["encrypt", "decrypt"], "DES", ("DES", "des", "des-ede", "des-cbc"),
    ),
    CanonicalEntry(
        "3DES", "1.2.840.113549.3.7", "cipher", "classically-broken", True,
        112, 0, ["encrypt", "decrypt"], "3DES", ("3DES", "TripleDES", "DES-EDE3", "triple-des", "des3"),
    ),
    CanonicalEntry(
        "RC2", "1.2.840.113549.3.2", "cipher", "classically-broken", True,
        64, 0, ["encrypt", "decrypt"], "RC2", ("RC2", "rc2"),
    ),
    CanonicalEntry(
        "RC4", "1.2.840.113549.3.4", "cipher", "classically-broken", True,
        128, 0, ["encrypt"], "RC4", ("RC4", "ARCFOUR", "rc4", "arcfour"),
    ),
    CanonicalEntry(
        "Blowfish", "1.3.6.1.4.1.3029.1.2", "cipher", "classically-broken", True,
        128, 0, ["encrypt", "decrypt"], "Blowfish", ("Blowfish", "blowfish"),
    ),

    # ---- Asymmetric key exchange (Shor-broken) ------------------------------
    CanonicalEntry(
        "RSA", "1.2.840.113549.1.1.1", "key-exchange", "shor", True,
        2048, 0, ["encrypt", "key-agreement"], "RSA-2048", ("RSA", "RSA2048", "RSA-2048", "rsa", "rsa-1024", "rsa-4096"),
    ),
    CanonicalEntry(
        "DH", "1.2.840.113549.1.3.1", "key-exchange", "shor", True,
        2048, 0, ["key-agreement"], "DH", ("DH", "DiffieHellman", "diffie-hellman", "dh"),
    ),
    CanonicalEntry(
        "ECDH", "1.2.840.10045.2.1", "key-exchange", "shor", True,
        256, 0, ["key-agreement"], "ECDH-P256", ("ECDH", "ecdh", "ECDH-P256", "ECDH-P384", "ECDH-P521"),
    ),
    CanonicalEntry(
        "X25519", "1.3.101.110", "key-exchange", "shor", True,
        128, 0, ["key-agreement"], "X25519", ("X25519", "x25519", "Curve25519"),
    ),
    CanonicalEntry(
        "X448", "1.3.101.111", "key-exchange", "shor", True,
        224, 0, ["key-agreement"], "X448", ("X448", "x448", "Curve448"),
    ),

    # ---- Digital signatures (Shor-broken) -----------------------------------
    CanonicalEntry(
        "RSA-PSS", "1.2.840.113549.1.1.10", "signature", "shor", True,
        2048, 0, ["sign", "verify"], "RSA-PSS", ("RSA-PSS", "RSASSA-PSS", "rsa-pss"),
    ),
    CanonicalEntry(
        "DSA", "1.2.840.10040.4.1", "signature", "shor", True,
        2048, 0, ["sign", "verify"], "DSA", ("DSA", "dsa"),
    ),
    CanonicalEntry(
        "ECDSA", "1.2.840.10045.4.1", "signature", "shor", True,
        256, 0, ["sign", "verify"], "ECDSA", ("ECDSA", "ecdsa", "ECDSA-P256", "ECDSA-P384"),
    ),
    CanonicalEntry(
        "Ed25519", "1.3.101.112", "signature", "shor", True,
        128, 0, ["sign", "verify"], "Ed25519", ("Ed25519", "ed25519", "ED25519"),
    ),
    CanonicalEntry(
        "Ed448", "1.3.101.113", "signature", "shor", True,
        224, 0, ["sign", "verify"], "Ed448", ("Ed448", "ed448", "ED448"),
    ),

    # ---- PQC Primitives (FIPS 203, 204, 205) --------------------------------
    CanonicalEntry(
        "ML-KEM-768", None, "key-exchange", "none", False,
        192, 3, ["key-agreement"], "ML-KEM-768", ("ML-KEM-768", "MLKEM768", "Kyber768", "kyber-768", "X25519MLKEM768"),
    ),
    CanonicalEntry(
        "ML-KEM-512", None, "key-exchange", "none", False,
        128, 1, ["key-agreement"], "ML-KEM-512", ("ML-KEM-512", "MLKEM512", "Kyber512", "kyber-512"),
    ),
    CanonicalEntry(
        "ML-KEM-1024", None, "key-exchange", "none", False,
        256, 5, ["key-agreement"], "ML-KEM-1024", ("ML-KEM-1024", "MLKEM1024", "Kyber1024", "kyber-1024"),
    ),
    CanonicalEntry(
        "ML-DSA-65", None, "signature", "none", False,
        192, 3, ["sign", "verify"], "ML-DSA-65", ("ML-DSA-65", "MLDSA65", "Dilithium3", "dilithium3"),
    ),
    CanonicalEntry(
        "ML-DSA-44", None, "signature", "none", False,
        128, 2, ["sign", "verify"], "ML-DSA-44", ("ML-DSA-44", "MLDSA44", "Dilithium2", "dilithium2"),
    ),
    CanonicalEntry(
        "ML-DSA-87", None, "signature", "none", False,
        256, 5, ["sign", "verify"], "ML-DSA-87", ("ML-DSA-87", "MLDSA87", "Dilithium5", "dilithium5"),
    ),
    CanonicalEntry(
        "SLH-DSA", None, "signature", "none", False,
        128, 1, ["sign", "verify"], "SLH-DSA", ("SLH-DSA", "SLHDSA", "SPHINCS+", "sphincs+"),
    ),
    CanonicalEntry(
        "FN-DSA", None, "signature", "none", False,
        128, 1, ["sign", "verify"], "FN-DSA", ("FN-DSA", "FNDSA", "Falcon", "falcon-512"),
    ),
    CanonicalEntry(
        "HQC", None, "key-exchange", "none", False,
        128, 1, ["key-agreement"], "HQC", ("HQC", "hqc-128"),
    ),
]

# Fast lookup map indexed by normalized alias
_ALIAS_MAP: dict[str, CanonicalEntry] = {}
for entry in _CANONICAL:
    # Key by canonical name normalized
    _ALIAS_MAP[_norm_alias(entry.canonical_name)] = entry
    # Key by all aliases normalized
    for alias in entry.aliases:
        _ALIAS_MAP[_norm_alias(alias)] = entry


def lookup_canonical(name: str) -> CanonicalEntry | None:
    """Lookup a canonical algorithm entry by raw name or alias."""
    if not name:
        return None

    norm = _norm_alias(name)
    if norm in _ALIAS_MAP:
        return _ALIAS_MAP[norm]

    # Substring search fallback for compound names (e.g., "AES/CBC/PKCS5Padding", "SHA1withRSA")
    for key, entry in _ALIAS_MAP.items():
        if len(key) >= 3 and (key in norm or norm in key):
            return entry

    return None


def get_canonical_entries() -> list[CanonicalEntry]:
    """Return all registered canonical entries."""
    return list(_CANONICAL)
