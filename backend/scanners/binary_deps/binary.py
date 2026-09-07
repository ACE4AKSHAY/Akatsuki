"""M2 binary scanner — strings + symbol extraction + matching.

Strategy (in priority order):
  1. Pure-Python strings fallback (always works, no toolchain).
  2. Try `pyelftools` for ELF symbol tables; `pefile` for PE symbols.
  3. Optionally shell out to `nm`, `strings`, `dumpbin` — best-effort, log warning.

Match against two curated lists embedded in code:
  - version banners: OpenSSL 1.0.2, OpenSSL 1.1.0, OpenSSL 3.0, BoringSSL,
                     LibreSSL, mbed TLS, wolfSSL
  - symbol names:    RSA_new, EVP_EncryptInit_ex, EVP_DigestInit_ex, MD5_Init,
                     SHA1_Init, DES_set_key, RC4

Emits one RawFinding per match, with `detectionTier` of `symbol-scan`
(when symbol table was used) or `binary-string` (strings-only fallback).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from backend.scanners._finding import RawFinding

VERSION_BANNERS = [
    ("OpenSSL 1.0.2", "OpenSSL 1.0.2 (deprecated EOL)"),
    ("OpenSSL 1.1.0", "OpenSSL 1.1.0 (deprecated EOL)"),
    ("OpenSSL 3.0", "OpenSSL 3.0 (modern)"),
    ("BoringSSL", "BoringSSL"),
    ("LibreSSL", "LibreSSL"),
    ("mbed TLS", "mbed TLS"),
    ("wolfSSL", "wolfSSL"),
]

SYMBOL_NAMES = [
    ("RSA_new", "RSA", "asymmetric-cipher"),
    ("EVP_EncryptInit_ex", "EVP", "symmetric-cipher"),
    ("EVP_DigestInit_ex", "EVP", "hash"),
    ("MD5_Init", "MD5", "hash"),
    ("SHA1_Init", "SHA1", "hash"),
    ("DES_set_key", "DES", "symmetric-cipher"),
    ("RC4", "RC4", "symmetric-cipher"),
]

STRINGS_RE = re.compile(rb"[\x20-\x7e]{6,}")


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------

def _strings_from_file(path: Path) -> list[str]:
    """Pure-Python strings extraction — always works."""
    try:
        data = path.read_bytes()
    except OSError:
        return []
    return [m.group(0).decode("ascii", errors="replace") for m in STRINGS_RE.finditer(data)]


def _symbols_from_elf(path: Path) -> list[str] | None:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return None
    try:
        with path.open("rb") as fh:
            elf = ELFFile(fh)
            names: list[str] = []
            for section in elf.iter_sections():
                if section.name == ".dynsym" or section.name == ".symtab":
                    for sym in section.iter_symbols():
                        if sym.name:
                            names.append(sym.name)
            return names
    except Exception:
        return None


def _symbols_from_pe(path: Path) -> list[str] | None:
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(path))
        names: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    names.append(exp.name.decode("utf-8", errors="replace"))
        return names
    except Exception:
        return None


def _shell_strings(path: Path) -> list[str] | None:
    binp = shutil.which("strings")
    if not binp:
        return None
    try:
        out = subprocess.run([binp, str(path)], capture_output=True, timeout=10, text=True)
        return [s for s in out.stdout.splitlines() if s]
    except Exception:
        return None


def _shell_nm(path: Path) -> list[str] | None:
    binp = shutil.which("nm")
    if not binp:
        return None
    try:
        out = subprocess.run([binp, "-D", str(path)], capture_output=True, timeout=10, text=True)
        return [line.split()[-1] for line in out.stdout.splitlines() if line]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Top-level binary scan
# ---------------------------------------------------------------------------

def scan_binary(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    """Run the binary scanner over a single file. Returns [] if no match."""
    p = Path(path)
    if not p.is_file():
        return []

    # Try symbol tables first (higher confidence).
    symbol_mode: str | None = None
    syms: list[str] | None = None
    if (syms := _symbols_from_elf(p)) is not None:
        symbol_mode = "elf"
    elif (syms := _symbols_from_pe(p)) is not None:
        symbol_mode = "pe"
    elif (syms := _shell_nm(p)) is not None:
        symbol_mode = "nm"
    else:
        syms = None

    if syms is not None and syms:
        findings = _match_symbols(syms, p, scan_target_id, symbol_mode or "symbol")
        if findings:
            return findings

    # Fall back to strings (pure-Python or shell).
    raw = _shell_strings(p) or _strings_from_file(p)
    return _match_strings(raw, p, scan_target_id)


def _match_symbols(syms: list[str], path: Path, scan_target_id: str, source: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    for sym, primitive, category in SYMBOL_NAMES:
        for s in syms:
            if s == sym or s.endswith("_" + sym):
                out.append(RawFinding(
                    sourceModule="M2_dep_binary_scanner",
                    scanTargetId=scan_target_id,
                    filePath=str(path),
                    lineNumber=1,
                    language=None,
                    library=source,
                    rawSignal=s,
                    detectedPrimitive=primitive,
                    primitiveCategory=category,
                    keySizeBits=None,
                    mode=None,
                    confidence=0.9,
                    detectionTier="symbol-scan",
                ))
                break
    return out


def _match_strings(strings: list[str], path: Path, scan_target_id: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    seen: set[str] = set()
    for s in strings:
        for banner, primitive in VERSION_BANNERS:
            if banner in s and banner not in seen:
                seen.add(banner)
                cat = "key-management"
                mode = "deprecated" if "deprecated" in primitive else None
                out.append(RawFinding(
                    sourceModule="M2_dep_binary_scanner",
                    scanTargetId=scan_target_id,
                    filePath=str(path),
                    lineNumber=1,
                    language=None,
                    library=None,
                    rawSignal=s.strip(),
                    detectedPrimitive=banner,
                    primitiveCategory=cat,
                    keySizeBits=None,
                    mode=mode,
                    confidence=0.7,
                    detectionTier="binary-string",
                ))
        for sym, primitive, category in SYMBOL_NAMES:
            if sym in s and primitive not in seen:
                seen.add(primitive)
                out.append(RawFinding(
                    sourceModule="M2_dep_binary_scanner",
                    scanTargetId=scan_target_id,
                    filePath=str(path),
                    lineNumber=1,
                    language=None,
                    library=None,
                    rawSignal=s.strip(),
                    detectedPrimitive=primitive,
                    primitiveCategory=category,
                    keySizeBits=None,
                    mode=None,
                    confidence=0.7,
                    detectionTier="binary-string",
                ))
    return out