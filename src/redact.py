"""Safe secret redaction utilities.

Secrets are NEVER stored or logged in full. This module provides the single
canonical place where masking is applied.
"""

from __future__ import annotations

_MASK_CHAR = "*"
_SHOW_PREFIX = 4
_SHOW_SUFFIX = 4
_MIN_MASK_LEN = 3  # minimum characters to replace with mask


def mask_secret(value: str) -> str:
    """Return a masked version of `value` showing only a prefix and suffix.

    Examples:
        "ghp_abcdefghijklmnopqrstuvwxyz123456" → "ghp_****...3456"
        "short" → "s***t"
        "AB" → "****"
    """
    if not value:
        return _MASK_CHAR * 4

    n = len(value)
    # For very short values, show nothing
    if n <= _SHOW_PREFIX:
        return _MASK_CHAR * max(n, 4)

    # Determine how many suffix chars to reveal
    suffix_len = _SHOW_SUFFIX if n > _SHOW_PREFIX + _SHOW_SUFFIX + _MIN_MASK_LEN else 0
    prefix = value[:_SHOW_PREFIX]
    suffix = value[-suffix_len:] if suffix_len else ""
    masked_len = n - _SHOW_PREFIX - suffix_len
    return f"{prefix}{_MASK_CHAR * max(masked_len, _MIN_MASK_LEN)}{suffix}"


def redact_line(line: str, col_start: int, col_end: int) -> str:
    """Replace the secret span in `line` with a masked representation."""
    if col_start < 0 or col_end > len(line) or col_start >= col_end:
        return line
    raw_secret = line[col_start:col_end]
    masked = mask_secret(raw_secret)
    return line[:col_start] + masked + line[col_end:]
