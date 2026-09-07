"""M1 Tier-2: tree-sitter AST confirmation pass.

For each file that produced at least one Tier-1 finding, parse the file with
the appropriate tree-sitter grammar and walk to find the enclosing call /
method_invocation / call_expression node for each hit. If the hit is inside
a real API call, rebuild the finding with `detectionTier="ast"`,
`confidence=0.95`, and (where possible) extracted args (AES key size, RSA
modulus, mode/padding). AST-confirmed findings supersede regex ones, dedup
key is (filePath, lineNumber, detectedPrimitive).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import tree_sitter_go as tsgo
import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjs
import tree_sitter_python as tspy
from tree_sitter import Language, Parser

from backend.scanners._finding import RawFinding
from backend.scanners.source.tier1 import EXT_TO_LANGUAGE, SOURCE_EXTENSIONS

_LANG_GRAMMARS = {
    "python": "python",
    "java": "java",
    "javascript": "javascript",
    "typescript": "typescript",
    "go": "go",
}

_LANG_PTRS = {
    "python": tspy.language(),
    "java": tsjava.language(),
    "javascript": tsjs.language(),
    "typescript": tsjs.language(),
    "go": tsgo.language(),
}

_PARSERS: dict[str, Parser] = {}


def _parser(language: str) -> Parser | None:
    if language not in _LANG_PTRS:
        return None
    if language not in _PARSERS:
        lang = Language(_LANG_PTRS[language], _LANG_GRAMMARS[language])
        p = Parser()
        p.set_language(lang)
        _PARSERS[language] = p
    return _PARSERS[language]


def _is_crypto_node_text(text: str) -> bool:
    """Heuristic: a call expression that names a known crypto verb."""
    crypto_verbs = (
        "MessageDigest", "Signature", "Cipher", "createHash", "createCipheriv",
        "generateKeyPairSync", "createSign", "createVerify", "Hash", "NewCipher",
        "NewSHA", "NewMD5", "NewSHA1", "NewSHA256", "GenerateKey", "sha1", "sha256",
        "md5", "rsa", "RSA_new", "EVP_EncryptInit_ex", "EVP_DigestInit_ex",
        "MD5_Init", "SHA1_Init", "DES_set_key", "algorithms.AES", "modes.ECB",
        "modes.CBC", "modes.GCM", "New", "modulusLength",
    )
    return any(verb in text for verb in crypto_verbs)


def _byte_to_line_col(src: bytes, offset: int) -> tuple[int, int]:
    snippet = src[:offset].decode("utf-8", errors="replace")
    line = snippet.count("\n") + 1
    last_nl = snippet.rfind("\n")
    col = offset - last_nl - 1 if last_nl != -1 else offset
    return line, col


def _walk(node, types: tuple[str, ...]):
    if node.type in types:
        yield node
    for child in node.children:
        yield from _walk(child, types)


def _line_for_offset(src: bytes, offset: int) -> int:
    """1-based line number containing `offset`."""
    return src[:offset].decode("utf-8", errors="replace").count("\n") + 1


def _find_smallest_call_containing(root, line: int, src: bytes):
    """Find the smallest `call` / `method_invocation` / `call_expression`
    node whose byte range includes `line`. Returns None if no such node.

    `line` is 1-based. A node is considered to "contain" line L if its
    start line is <= L and its end line is >= L (in 1-based terms).
    """
    candidates = []
    for n in _walk(root, ("call", "call_expression", "method_invocation")):
        start_line = _line_for_offset(src, n.start_byte)
        end_line = _line_for_offset(src, max(n.end_byte - 1, n.start_byte))
        if start_line <= line <= end_line:
            candidates.append((n.end_byte - n.start_byte, n))
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    return candidates[0][1]


def _extract_args(node, src: bytes) -> dict:
    """Pull (key size, mode/padding) out of a call node by text inspection."""
    text = src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
    out: dict = {}
    m = re.search(r"aes-(\d+)-(\w+)", text)
    if m:
        out["keySizeBits"] = int(m.group(1))
        out["mode"] = m.group(2).upper()
    m = re.search(r"key_size\s*=\s*(\d+)", text)
    if m:
        out["keySizeBits"] = int(m.group(1))
    m = re.search(r"modulusLength\s*:\s*(\d+)", text)
    if m:
        out["keySizeBits"] = int(m.group(1))
    m = re.search(r"MessageDigest\.getInstance\(['\"]([\w-]+)['\"]\)", text)
    if m:
        out["hashAlg"] = m.group(1)
    m = re.search(r"Cipher\.getInstance\(['\"]([\w/]+)['\"]\)", text)
    if m:
        parts = m.group(1).split("/")
        if len(parts) >= 2:
            out["mode"] = parts[1]
    return out


def _confirm_one(hit: RawFinding, src: bytes) -> RawFinding | None:
    """Confirm a single Tier-1 hit via the AST.

    Returns a new (AST-confirmed) finding, or None if the hit doesn't
    resolve to a real crypto API call.
    """
    parser = _parser(hit.language or "")
    if parser is None:
        return None
    tree = parser.parse(src)
    line = hit.lineNumber
    call_node = _find_smallest_call_containing(tree.root_node, line, src)
    if call_node is None:
        # Special case: hits that are just identifiers (e.g. `crypto/sha1`
        # import). Confirm if the identifier token is on a known import line.
        # We treat those as import-level signal and downgrade confidence but keep them.
        snippet = src.decode("utf-8", errors="replace").splitlines()[line - 1]
        if (re.match(r"\s*import\s+", snippet)
                or re.match(r"\s*from\s+", snippet)
                or re.match(r'\s*"crypto/', snippet)
                or re.match(r"\s*package\s+", snippet)):
            return hit.model_copy(update={
                "detectionTier": "ast",
                "confidence": 0.85,
                "library": snippet.strip().strip('"'),
            })
        return None
    text = src[call_node.start_byte:call_node.end_byte].decode("utf-8", errors="replace")
    if not _is_crypto_node_text(text):
        return None
    args = _extract_args(call_node, src)
    update = {
        "detectionTier": "ast",
        "confidence": 0.95,
        "library": hit.library,
        "rawSignal": text.strip(),
    }
    if "keySizeBits" in args:
        update["keySizeBits"] = args["keySizeBits"]
    if "mode" in args:
        update["mode"] = args["mode"]
    if "hashAlg" in args:
        update["rawSignal"] = f"MessageDigest.getInstance({args['hashAlg']!r})"
    return hit.model_copy(update=update)


def _byte_to_offset(src: bytes, line: int, col: int) -> int:
    """Return byte offset for (1-based line, 0-based col)."""
    cur = 0
    cur_line = 1
    while cur_line < line:
        nl = src.find(b"\n", cur)
        if nl == -1:
            return len(src)
        cur = nl + 1
        cur_line += 1
    return cur + col


def confirm(findings: list[RawFinding]) -> list[RawFinding]:
    """Given Tier-1 findings, return AST-confirmed findings (replaces regex ones)."""
    by_file: dict[str, list[RawFinding]] = {}
    for f in findings:
        by_file.setdefault(f.filePath, []).append(f)

    confirmed: list[RawFinding] = []
    for fpath, group in by_file.items():
        try:
            src = Path(fpath).read_bytes()
        except OSError:
            # Can't AST-confirm — keep the regex hits as-is.
            confirmed.extend(group)
            continue
        for hit in group:
            new = _confirm_one(hit, src)
            if new is not None:
                confirmed.append(new)

    # Dedup: (filePath, lineNumber, detectedPrimitive) — AST wins over regex.
    best: dict[tuple[str, int, str], RawFinding] = {}
    for f in confirmed:
        key = (f.filePath, f.lineNumber, f.detectedPrimitive)
        cur = best.get(key)
        if cur is None or f.detectionTier == "ast" or f.confidence > cur.confidence:
            best[key] = f
    return list(best.values())