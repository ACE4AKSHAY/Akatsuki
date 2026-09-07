"""RawFinding Pydantic model — LOCK-POINT file.

This file is the single source of truth for the M1/M2/M3 RawFinding shape.
Per CONTRACT.md (owned by Person B), §1 is frozen. If a v1.1 field is added,
this is the only file that should change to match (plus the parallel
shared/schemas/raw_finding.schema.json).

Every scanner in backend/scanners/{source,binary_deps,infra}/ MUST build
findings via RawFinding(...) so field names, defaults, and the
`null`-for-N/A rule are enforced uniformly.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SourceModule = Literal[
    "M1_source_scanner",
    "M2_dep_binary_scanner",
    "M3_container_config_scanner",
]

DetectionTier = Literal[
    "regex",
    "ast",
    "manifest",
    "symbol-scan",
    "binary-string",
    "dockerfile",
    "config-parse",
    "iac-parse",
    "cert-parse",
]

PrimitiveCategory = Literal[
    "hash",
    "symmetric-cipher",
    "asymmetric-cipher",
    "signature",
    "mac",
    "kdf",
    "protocol",
    "cipher",
    "certificate",
    "key-management",
]


class RawFinding(BaseModel):
    """A single raw finding emitted by M1, M2, or M3.

    Field names and defaults mirror CONTRACT.md §1 verbatim.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    sourceModule: SourceModule
    scanTargetId: str
    filePath: str
    lineNumber: int
    language: Optional[str] = None
    library: Optional[str] = None
    rawSignal: str
    detectedPrimitive: str
    primitiveCategory: PrimitiveCategory
    keySizeBits: Optional[int] = None
    mode: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    detectionTier: DetectionTier

    def to_dict(self) -> dict:
        """Serialise with explicit `null`s for N/A fields (CONTRACT §1 rule)."""
        d = self.model_dump()
        return d