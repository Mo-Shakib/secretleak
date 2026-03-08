"""Tests for secret redaction utilities."""

from __future__ import annotations

from secretleak.redact import mask_secret, redact_line


class TestMaskSecret:
    def test_long_secret_shows_prefix_and_suffix(self) -> None:
        masked = mask_secret("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
        assert masked.startswith("ghp_")
        assert masked.endswith("3456")
        assert "***" in masked
        # Full value must NOT appear in masked form
        assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in masked

    def test_short_secret_fully_masked(self) -> None:
        masked = mask_secret("AB")
        assert "AB" not in masked
        assert "*" in masked

    def test_empty_secret(self) -> None:
        masked = mask_secret("")
        assert masked == "****"

    def test_exact_prefix_length_secret(self) -> None:
        # Length == _SHOW_PREFIX (4), no suffix revealed
        masked = mask_secret("ABCD")
        assert "ABCD" not in masked

    def test_no_raw_secret_leaked(self) -> None:
        # Constructed at runtime so the source file contains no credential literal
        raw = "sk_" + "live" + "_" + "A" * 24
        masked = mask_secret(raw)
        # Only first 4 chars visible
        assert raw[4:] not in masked


class TestRedactLine:
    def test_replaces_span_in_line(self) -> None:
        line = "API_KEY=sk_test_secretvalue12345678"
        col_start = 8
        col_end = len(line)
        redacted = redact_line(line, col_start, col_end)
        assert "sk_te" not in redacted  # full secret not visible
        assert redacted.startswith("API_KEY=")

    def test_invalid_span_returns_unchanged(self) -> None:
        line = "hello world"
        assert redact_line(line, -1, 5) == line
        assert redact_line(line, 5, 3) == line
        assert redact_line(line, 0, 100) == line

    def test_entire_line_redacted(self) -> None:
        line = "secretvalue"
        redacted = redact_line(line, 0, len(line))
        assert "secretvalue" not in redacted
