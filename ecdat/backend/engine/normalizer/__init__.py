"""M4 CBOM Aggregation & Normalization Engine package."""

from backend.engine.normalizer.canonical import (
    CanonicalEntry,
    get_canonical_entries,
    lookup_canonical,
)
from backend.engine.normalizer.normalizer import (
    DEFAULT_TAGGING,
    PATH_TAG_PATTERNS,
    build_cbom_document,
    normalize,
    resolve_tagging,
)

from backend.engine.normalizer.validator import (
    CBOMValidationError,
    assert_valid_cbom,
    validate_cbom_asset,
    validate_cbom_document,
)

__all__ = [
    "CBOMValidationError",
    "CanonicalEntry",
    "DEFAULT_TAGGING",
    "PATH_TAG_PATTERNS",
    "assert_valid_cbom",
    "build_cbom_document",
    "get_canonical_entries",
    "lookup_canonical",
    "normalize",
    "resolve_tagging",
    "validate_cbom_asset",
    "validate_cbom_document",
]
