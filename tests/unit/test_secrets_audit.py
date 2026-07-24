"""Tests for cyberjection.security.secrets_audit.

`scan_text_for_secrets` is exercised directly with adversarial and benign
strings (no filesystem access needed); `scan_paths_for_secrets` and
`scan_campaign_config_for_hardcoded_secrets` get their own filesystem- and
YAML-shaped tests respectively.
"""

from __future__ import annotations

from pathlib import Path

from cyberjection.security.secrets_audit import (
    scan_campaign_config_for_hardcoded_secrets,
    scan_paths_for_secrets,
    scan_text_for_secrets,
)


class TestScanTextForSecrets:
    def test_aws_access_key_id_is_flagged(self) -> None:
        # Deliberately not AWS's well-known "AKIA...EXAMPLE" documentation
        # key -- it contains "EXAMPLE", which _looks_like_placeholder()
        # correctly treats as a placeholder marker and skips, so a test
        # built on it would pass for the wrong reason (or not at all).
        findings = scan_text_for_secrets("AKIAQWERTYUIOPASDFGH", source_label="<test>")
        assert any(f.pattern_name == "aws_access_key_id" for f in findings)

    def test_aws_secret_access_key_is_flagged(self) -> None:
        text = 'aws_secret_access_key = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"'
        findings = scan_text_for_secrets(text, source_label="<test>")
        assert any(f.pattern_name == "aws_secret_access_key" for f in findings)

    def test_private_key_header_is_flagged(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
        findings = scan_text_for_secrets(text, source_label="<test>")
        assert any(f.pattern_name == "private_key_header" for f in findings)

    def test_slack_token_is_flagged(self) -> None:
        text = "SLACK_TOKEN=xoxb-1234567890-abcdefghijklmnop"
        findings = scan_text_for_secrets(text, source_label="<test>")
        assert any(f.pattern_name == "slack_token" for f in findings)

    def test_github_token_is_flagged(self) -> None:
        text = "token: ghp_" + "a" * 36
        findings = scan_text_for_secrets(text, source_label="<test>")
        assert any(f.pattern_name == "github_token" for f in findings)

    def test_generic_api_key_assignment_is_flagged(self) -> None:
        text = 'api_key = "sk-abcdef0123456789ABCDEF"'
        findings = scan_text_for_secrets(text, source_label="<test>")
        assert any(f.pattern_name == "generic_api_key_assignment" for f in findings)

    def test_placeholder_values_are_not_flagged(self) -> None:
        text = 'api_key: "your-api-key-here"'
        findings = scan_text_for_secrets(text, source_label="<test>")
        assert findings == []

    def test_env_interpolation_placeholder_is_not_flagged(self) -> None:
        text = "api_key: ${OPENAI_API_KEY}"
        findings = scan_text_for_secrets(text, source_label="<test>")
        assert findings == []

    def test_ordinary_benign_text_produces_no_findings(self) -> None:
        text = "This is a normal README paragraph about the project.\nNothing sensitive here."
        assert scan_text_for_secrets(text, source_label="<test>") == []

    def test_line_numbers_are_1_indexed_and_correct(self) -> None:
        text = "line one\nline two\nAKIAQWERTYUIOPASDFGH\nline four"
        findings = scan_text_for_secrets(text, source_label="<test>")
        assert len(findings) == 1
        assert findings[0].line == 3

    def test_excerpt_never_contains_the_raw_matched_secret(self) -> None:
        raw_secret = "AKIAQWERTYUIOPASDFGH"
        findings = scan_text_for_secrets(raw_secret, source_label="<test>")
        assert len(findings) == 1
        assert raw_secret not in findings[0].excerpt

    def test_source_label_is_carried_through(self) -> None:
        findings = scan_text_for_secrets("AKIAQWERTYUIOPASDFGH", source_label="config/prod.yaml")
        assert findings[0].source == "config/prod.yaml"


class TestScanPathsForSecrets:
    def test_scans_a_single_file(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.py"
        target.write_text('AWS_KEY = "AKIAQWERTYUIOPASDFGH"\n', encoding="utf-8")
        findings = scan_paths_for_secrets([target])
        assert len(findings) == 1
        assert findings[0].source == str(target)

    def test_walks_a_directory_recursively(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "leaked.txt").write_text("AKIAQWERTYUIOPASDFGH\n", encoding="utf-8")
        (tmp_path / "clean.txt").write_text("nothing here\n", encoding="utf-8")
        findings = scan_paths_for_secrets([tmp_path])
        assert len(findings) == 1

    def test_excluded_dirs_are_skipped(self, tmp_path: Path) -> None:
        excluded = tmp_path / ".git"
        excluded.mkdir()
        (excluded / "config").write_text("AKIAQWERTYUIOPASDFGH\n", encoding="utf-8")
        findings = scan_paths_for_secrets([tmp_path])
        assert findings == []

    def test_binary_files_are_skipped_without_raising(self, tmp_path: Path) -> None:
        binary = tmp_path / "image.bin"
        binary.write_bytes(bytes(range(256)))
        # Must not raise UnicodeDecodeError.
        findings = scan_paths_for_secrets([tmp_path])
        assert findings == []

    def test_nonexistent_path_produces_no_findings_and_does_not_raise(self, tmp_path: Path) -> None:
        findings = scan_paths_for_secrets([tmp_path / "does_not_exist"])
        assert findings == []


class TestScanCampaignConfigForHardcodedSecrets:
    def test_literal_api_key_value_is_flagged(self) -> None:
        yaml_text = 'targets:\n  - id: t1\n    api_key: "sk-live-abcdef1234567890"\n'
        findings = scan_campaign_config_for_hardcoded_secrets(yaml_text)
        assert len(findings) == 1
        assert findings[0].pattern_name == "hardcoded_api_key"

    def test_env_var_interpolated_api_key_is_not_flagged(self) -> None:
        yaml_text = 'targets:\n  - id: t1\n    api_key: "${OPENAI_API_KEY}"\n'
        assert scan_campaign_config_for_hardcoded_secrets(yaml_text) == []

    def test_empty_api_key_value_is_not_flagged(self) -> None:
        yaml_text = "targets:\n  - id: t1\n    api_key:\n"
        assert scan_campaign_config_for_hardcoded_secrets(yaml_text) == []

    def test_unrelated_fields_are_ignored(self) -> None:
        yaml_text = 'targets:\n  - id: t1\n    system_prompt: "you are a helpful assistant"\n'
        assert scan_campaign_config_for_hardcoded_secrets(yaml_text) == []

    def test_source_label_defaults_to_config_placeholder(self) -> None:
        yaml_text = 'api_key: "literal-value-not-interpolated"\n'
        findings = scan_campaign_config_for_hardcoded_secrets(yaml_text)
        assert findings[0].source == "<config>"

    def test_custom_source_label_is_used(self) -> None:
        yaml_text = 'api_key: "literal-value-not-interpolated"\n'
        findings = scan_campaign_config_for_hardcoded_secrets(yaml_text, source_label="examples/quickstart.yaml")
        assert findings[0].source == "examples/quickstart.yaml"
