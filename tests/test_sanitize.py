"""Unit tests for input sanitisation and ID validation.

These tests cover the _sanitize() and _validate_id() helpers used
throughout the ops modules as a prompt-injection defence layer.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Import helpers directly from the ops modules (they are module-private but
# identical across modules, so we test one representative copy)
# ---------------------------------------------------------------------------


def _get_helpers():
    """Import _sanitize and _validate_id from dfw_policy module."""
    from vmware_nsx_security.ops.dfw_policy import _sanitize, _validate_id  # noqa: PLC2701
    return _sanitize, _validate_id


# ---------------------------------------------------------------------------
# _sanitize tests
# ---------------------------------------------------------------------------


class TestSanitize:
    """Tests for the _sanitize() helper."""

    def test_normal_string_unchanged(self):
        """Regular text is returned unchanged."""
        _sanitize, _ = _get_helpers()
        assert _sanitize("hello world") == "hello world"

    def test_empty_string(self):
        """Empty string returns empty string."""
        _sanitize, _ = _get_helpers()
        assert _sanitize("") == ""

    def test_strips_null_bytes(self):
        """Null bytes are removed."""
        _sanitize, _ = _get_helpers()
        assert _sanitize("abc\x00def") == "abcdef"

    def test_strips_control_chars(self):
        """ASCII control characters (0x01-0x08, 0x0b, etc.) are removed."""
        _sanitize, _ = _get_helpers()
        assert _sanitize("abc\x01\x07def") == "abcdef"

    def test_strips_high_control_chars(self):
        """High control characters (0x7f-0x9f) are removed."""
        _sanitize, _ = _get_helpers()
        assert _sanitize("abc\x7fdef\x9f") == "abcdef"

    def test_preserves_newline_and_tab(self):
        """Newline (0x0a) and tab (0x09) are preserved."""
        _sanitize, _ = _get_helpers()
        assert _sanitize("line1\nline2") == "line1\nline2"
        assert _sanitize("col1\tcol2") == "col1\tcol2"

    def test_truncates_to_max_len(self):
        """Strings longer than max_len are truncated."""
        _sanitize, _ = _get_helpers()
        long_str = "a" * 1000
        result = _sanitize(long_str, max_len=100)
        assert len(result) == 100

    def test_default_max_len_500(self):
        """Default max_len is 500."""
        _sanitize, _ = _get_helpers()
        long_str = "x" * 600
        result = _sanitize(long_str)
        assert len(result) == 500

    def test_unicode_preserved(self):
        """Unicode characters outside control range are preserved."""
        _sanitize, _ = _get_helpers()
        assert _sanitize("中文abc") == "中文abc"

    def test_prompt_injection_attempt(self):
        """Prompt injection via control chars is neutralised."""
        _sanitize, _ = _get_helpers()
        evil = "normal\x1b[31mred text\x1b[0m"
        result = _sanitize(evil)
        assert "\x1b" not in result
        assert "normal" in result


# ---------------------------------------------------------------------------
# _validate_id tests
# ---------------------------------------------------------------------------


class TestValidateId:
    """Tests for the _validate_id() helper."""

    def test_simple_alphanumeric(self):
        """Simple alphanumeric IDs are accepted."""
        _, _validate_id = _get_helpers()
        assert _validate_id("myPolicy123") == "myPolicy123"

    def test_hyphens_allowed(self):
        """Hyphens are allowed in IDs."""
        _, _validate_id = _get_helpers()
        assert _validate_id("app-tier-policy") == "app-tier-policy"

    def test_underscores_allowed(self):
        """Underscores are allowed in IDs."""
        _, _validate_id = _get_helpers()
        assert _validate_id("web_tier_01") == "web_tier_01"

    def test_dots_allowed(self):
        """Dots are allowed in IDs."""
        _, _validate_id = _get_helpers()
        assert _validate_id("policy.v1.0") == "policy.v1.0"

    def test_spaces_rejected(self):
        """IDs with spaces raise ValueError."""
        _, _validate_id = _get_helpers()
        with pytest.raises(ValueError, match="Invalid"):
            _validate_id("policy with spaces")

    def test_slash_rejected(self):
        """IDs with slashes raise ValueError (path traversal prevention)."""
        _, _validate_id = _get_helpers()
        with pytest.raises(ValueError, match="Invalid"):
            _validate_id("../../etc/passwd")

    def test_semicolon_rejected(self):
        """IDs with semicolons raise ValueError."""
        _, _validate_id = _get_helpers()
        with pytest.raises(ValueError, match="Invalid"):
            _validate_id("id;DROP TABLE")

    def test_empty_string_rejected(self):
        """Empty IDs raise ValueError."""
        _, _validate_id = _get_helpers()
        with pytest.raises(ValueError, match="Invalid"):
            _validate_id("")

    def test_field_name_in_error(self):
        """Error message includes the field name for context."""
        _, _validate_id = _get_helpers()
        with pytest.raises(ValueError, match="policy_id"):
            _validate_id("bad id!", field="policy_id")
