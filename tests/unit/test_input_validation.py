"""Tests for cyberjection.security.input_validation.

Covers the three independent guards this module provides: output-path
containment (`assert_safe_output_path`), target-URL SSRF checks
(`assert_safe_target_url`), and payload size enforcement
(`enforce_payload_size_limit`). All three are pure/local-filesystem-only
functions with no network or subprocess dependency, so this suite runs
identically in every environment, including this project's offline
sandbox.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberjection.security.input_validation import (
    DEFAULT_MAX_PAYLOAD_BYTES,
    assert_safe_output_path,
    assert_safe_target_url,
    enforce_payload_size_limit,
)
from cyberjection.utils.exceptions import PathTraversalError, PayloadTooLargeError, UnsafeTargetURLError


class TestAssertSafeOutputPath:
    def test_relative_path_within_base_is_allowed(self, tmp_path: Path) -> None:
        resolved = assert_safe_output_path("reports/out.json", base_dir=tmp_path)
        assert resolved == (tmp_path / "reports" / "out.json").resolve()

    def test_absolute_path_within_base_is_allowed(self, tmp_path: Path) -> None:
        target = tmp_path / "out.json"
        resolved = assert_safe_output_path(target, base_dir=tmp_path)
        assert resolved == target.resolve()

    def test_absolute_path_outside_base_is_allowed_as_an_explicit_choice(self, tmp_path: Path) -> None:
        # An absolute path is the operator's deliberate, explicit choice
        # (e.g. writing a report to a CI artifacts mount outside the repo
        # working tree) -- see assert_safe_output_path's docstring for why
        # this function only guards relative-path escapes, not absolute
        # destinations the caller typed out in full.
        outside = tmp_path.parent / "explicit_out.json"
        resolved = assert_safe_output_path(outside, base_dir=tmp_path)
        assert resolved == outside.resolve()

    def test_dotdot_traversal_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(PathTraversalError):
            assert_safe_output_path("../../etc/passwd", base_dir=tmp_path)

    def test_nested_dotdot_that_still_escapes_is_rejected(self, tmp_path: Path) -> None:
        # "reports/../../out.json" collapses to a path one level above
        # base_dir even though it doesn't look like an obvious escape at
        # a glance -- Path.resolve() must actually collapse it before the
        # relative_to() containment check runs, not just string-match "..".
        with pytest.raises(PathTraversalError):
            assert_safe_output_path("reports/../../out.json", base_dir=tmp_path)

    def test_relative_path_through_a_symlink_escaping_base_dir_is_rejected(self, tmp_path: Path) -> None:
        # The symlink-escape scenario this guard actually defends against:
        # a *relative* filename that looks contained but is itself a
        # symlink (planted inside an otherwise-trusted output directory)
        # pointing outside it.
        outside = tmp_path.parent / "outside_target.json"
        outside.write_text("{}", encoding="utf-8")
        base = tmp_path / "base"
        base.mkdir()
        link = base / "escape.json"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("symlinks not supported in this environment")
        with pytest.raises(PathTraversalError):
            assert_safe_output_path("escape.json", base_dir=base)

    def test_path_equal_to_base_dir_itself_is_allowed(self, tmp_path: Path) -> None:
        resolved = assert_safe_output_path(".", base_dir=tmp_path)
        assert resolved == tmp_path.resolve()


class TestAssertSafeTargetURL:
    def test_ordinary_https_url_is_allowed(self) -> None:
        assert assert_safe_target_url("https://api.openai.com/v1") == "https://api.openai.com/v1"

    def test_ordinary_http_url_is_allowed(self) -> None:
        assert assert_safe_target_url("http://example.com/api") == "http://example.com/api"

    def test_non_http_scheme_is_rejected(self) -> None:
        with pytest.raises(UnsafeTargetURLError):
            assert_safe_target_url("file:///etc/passwd")

    def test_blocked_hostname_is_rejected(self) -> None:
        with pytest.raises(UnsafeTargetURLError):
            assert_safe_target_url("http://localhost:11434")

    def test_cloud_metadata_literal_ip_is_rejected(self) -> None:
        with pytest.raises(UnsafeTargetURLError):
            assert_safe_target_url("http://169.254.169.254/latest/meta-data/")

    def test_loopback_literal_ip_is_rejected(self) -> None:
        with pytest.raises(UnsafeTargetURLError):
            assert_safe_target_url("http://127.0.0.1:8000")

    def test_private_network_literal_ip_is_rejected(self) -> None:
        with pytest.raises(UnsafeTargetURLError):
            assert_safe_target_url("http://10.0.0.5/v1")

    def test_link_local_literal_ip_is_rejected(self) -> None:
        with pytest.raises(UnsafeTargetURLError):
            assert_safe_target_url("http://169.254.1.1/v1")

    def test_localhost_allowed_with_explicit_opt_in(self) -> None:
        result = assert_safe_target_url("http://localhost:11434", allow_private_networks=True)
        assert result == "http://localhost:11434"

    def test_private_ip_allowed_with_explicit_opt_in(self) -> None:
        result = assert_safe_target_url("http://10.0.0.5/v1", allow_private_networks=True)
        assert result == "http://10.0.0.5/v1"

    def test_public_ip_literal_is_allowed(self) -> None:
        assert assert_safe_target_url("http://8.8.8.8/v1") == "http://8.8.8.8/v1"

    def test_hostname_that_is_not_a_literal_ip_is_not_resolved(self) -> None:
        # A DNS hostname (as opposed to a literal IP) is deliberately not
        # resolved by this validator -- see the module docstring's
        # rationale about avoiding a TOCTOU DNS-rebinding false sense of
        # safety. A hostname that isn't on the blocked list passes.
        assert assert_safe_target_url("https://my-private-model-host.internal/v1")


class TestEnforcePayloadSizeLimit:
    def test_payload_within_limit_is_returned_unchanged(self) -> None:
        text = "hello world"
        assert enforce_payload_size_limit(text) == text

    def test_payload_exactly_at_limit_is_allowed(self) -> None:
        text = "a" * 100
        assert enforce_payload_size_limit(text, max_bytes=100) == text

    def test_payload_over_limit_is_rejected(self) -> None:
        text = "a" * 101
        with pytest.raises(PayloadTooLargeError):
            enforce_payload_size_limit(text, max_bytes=100)

    def test_default_limit_is_used_when_not_specified(self) -> None:
        text = "a" * (DEFAULT_MAX_PAYLOAD_BYTES + 1)
        with pytest.raises(PayloadTooLargeError):
            enforce_payload_size_limit(text)

    def test_multibyte_utf8_is_measured_in_bytes_not_characters(self) -> None:
        # Each of these characters is 3 bytes in UTF-8; 40 characters is
        # 120 bytes, which must be rejected against a 100-byte limit even
        # though len(text) == 40 (character count) would pass.
        text = "☃" * 40  # snowman
        assert len(text) == 40
        with pytest.raises(PayloadTooLargeError):
            enforce_payload_size_limit(text, max_bytes=100)

    def test_error_message_includes_label(self) -> None:
        with pytest.raises(PayloadTooLargeError, match="response body"):
            enforce_payload_size_limit("a" * 10, max_bytes=1, label="response body")
