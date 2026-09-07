"""M1 Tier-1: fast regex pass over a single file.

Contract: returns `list[RawFinding]` with `detectionTier="regex"`,
`confidence=0.6`. Tier-2 in tier2.py will overwrite these with AST-confirmed
findings (`detectionTier="ast"`, `confidence=0.95`).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from backend.scanners._finding import RawFinding
from backend.scanners.source.config import load_signals

SOURCE_EXTENSIONS = {".py", ".java", ".js", ".ts", ".mjs", ".go", ".jsx", ".tsx"}

EXT_TO_LANGUAGE = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
}


def _is_python_comment(line_text: str, col: int) -> bool:
    """Tiny pre-filter: drop hits inside `#` comments for Python only.

    `line_text` is the entire line containing the match. `col` is 0-based.
    Returns True if the match is inside a `#` comment, in which case the
    Tier-1 hit should be suppressed.
    """
    hash_at = line_text.find("#")
    if hash_at == -1 or col < hash_at:
        return False
    # Inside a triple-quoted string? bail out (we don't try to parse it).
    # Cheap heuristic: look for `"""` or `'''` before the hash.
    before = line_text[:hash_at]
    if before.count('"""') % 2 == 1 or before.count("'''") % 2 == 1:
        return False
    return True


def _is_python_string_literal(line_text: str, col: int) -> bool:
    """Cheap pre-filter: drop hits inside triple-quoted strings for Python."""
    if '"""' in line_text or "'''" in line_text:
        return False
    return False


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset - last_nl - 1 if last_nl != -1 else offset
    return line, col


def scan_file(
    path: str | Path,
    *,
    scan_target_id: str,
    language: str | None = None,
) -> list[RawFinding]:
    """Run the Tier-1 regex pass over a single file. Returns [] on any error."""
    p = Path(path)
    if not p.is_file():
        return []
    ext = p.suffix.lower()
    if ext not in SOURCE_EXTENSIONS:
        return []
    lang = language or EXT_TO_LANGUAGE.get(ext, "unknown")

    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[RawFinding] = []
    lines = text.splitlines()
    for sig in load_signals():
        for pat in sig.get("patterns", []):
            try:
                rx = re.compile(pat)
            except re.error:
                continue
            for m in rx.finditer(text):
                offset = m.start()
                line_no, col = _line_col(text, offset)
                if ext == ".py":
                    line_text = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                    if _is_python_comment(line_text, col):
                        continue
                key_size = sig.get("keySizeBits")
                mode = sig.get("mode")
                # Heuristic: extract AES mode from createCipheriv arg if present
                if sig.get("id") == "AES":
                    mg = re.search(r"aes-(\d+)-(\w+)", m.group(0), re.IGNORECASE)
                    if mg:
                        try:
                            key_size = int(mg.group(1))
                        except ValueError:
                            pass
                        mode = mg.group(2).upper()
                findings.append(
                    RawFinding(
                        sourceModule="M1_source_scanner",
                        scanTargetId=scan_target_id,
                        filePath=str(p),
                        lineNumber=line_no,
                        language=lang,
                        library=None,
                        rawSignal=m.group(0),
                        detectedPrimitive=sig["primitive"],
                        primitiveCategory=sig["primitiveCategory"],
                        keySizeBits=key_size,
                        mode=mode,
                        confidence=0.6,
                        detectionTier="regex",
                    )
                )
    return findings


def iter_source_files(root: str | Path) -> Iterable[Path]:
    """Yield candidate source files under `root`."""
    root = Path(root)
    if root.is_file():
        if root.suffix.lower() in SOURCE_EXTENSIONS:
            yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS:
            yield p
