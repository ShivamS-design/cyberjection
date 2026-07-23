"""Tests for cyberjection.config.loader: YAML loading & env var expansion."""

from __future__ import annotations

import pytest

from cyberjection.config.loader import expand_env_vars, load_config, load_config_from_string
from cyberjection.utils.exceptions import ConfigValidationError

MINIMAL_CAMPAIGN = """
name: "Test Campaign"
targets:
  - id: "t1"
    provider: "openai"
    model: "gpt-4o-mini"
    api_key: "${OPENAI_API_KEY}"
"""


class TestExpandEnvVars:
    def test_substitutes_known_variable(self) -> None:
        result = expand_env_vars("key: ${FOO}", env={"FOO": "bar"})
        assert result == "key: bar"

    def test_uses_inline_default_when_unset(self) -> None:
        result = expand_env_vars("key: ${FOO:-fallback}", env={})
        assert result == "key: fallback"

    def test_env_value_takes_precedence_over_default(self) -> None:
        result = expand_env_vars("key: ${FOO:-fallback}", env={"FOO": "real"})
        assert result == "key: real"

    def test_strict_raises_on_missing_variable(self) -> None:
        with pytest.raises(ConfigValidationError, match="FOO"):
            expand_env_vars("key: ${FOO}", env={}, strict=True)

    def test_non_strict_resolves_missing_to_empty_string(self) -> None:
        result = expand_env_vars("key: ${FOO}", env={}, strict=False)
        assert result == "key: "

    def test_multiple_variables_in_one_document(self) -> None:
        result = expand_env_vars(
            "a: ${A}\nb: ${B}",
            env={"A": "1", "B": "2"},
        )
        assert result == "a: 1\nb: 2"

    def test_reports_all_missing_variables_at_once(self) -> None:
        with pytest.raises(ConfigValidationError) as exc_info:
            expand_env_vars("a: ${A}\nb: ${B}", env={}, strict=True)
        assert "A" in str(exc_info.value)
        assert "B" in str(exc_info.value)

    def test_expansion_is_single_pass_not_recursive(self) -> None:
        """Regression / security check: if OUTER resolves to a string that
        itself looks like ${INNER}, that must NOT be re-expanded. A second
        substitution pass would let an attacker who controls one env var
        (or a value read from an untrusted source) smuggle in a reference
        to a second, more sensitive variable."""

        result = expand_env_vars(
            "val: ${OUTER}",
            env={"OUTER": "${INNER}", "INNER": "should-not-appear"},
        )
        assert result == "val: ${INNER}"


class TestLoadConfigFromString:
    def test_loads_valid_campaign(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
        config = load_config_from_string(MINIMAL_CAMPAIGN)
        assert config.name == "Test Campaign"
        assert config.targets[0].api_key.get_secret_value() == "sk-test-123"

    def test_missing_env_var_raises_config_error(self, clean_env: None) -> None:
        with pytest.raises(ConfigValidationError):
            load_config_from_string(MINIMAL_CAMPAIGN)

    def test_malformed_yaml_raises_config_error(self) -> None:
        with pytest.raises(ConfigValidationError, match="parse YAML"):
            load_config_from_string("name: [unclosed")

    def test_empty_document_raises_config_error(self) -> None:
        with pytest.raises(ConfigValidationError, match="empty"):
            load_config_from_string("")

    def test_non_mapping_document_raises_config_error(self) -> None:
        with pytest.raises(ConfigValidationError, match="mapping"):
            load_config_from_string("- 1\n- 2\n")

    def test_schema_validation_failure_raises_config_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
        bad_yaml = MINIMAL_CAMPAIGN + "\nmax_cost_cap: -5.0\n"
        with pytest.raises(ConfigValidationError, match="schema validation"):
            load_config_from_string(bad_yaml)


class TestLoadConfigFromFile:
    def test_loads_config_from_disk(self, tmp_yaml_file, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
        path = tmp_yaml_file(MINIMAL_CAMPAIGN)
        config = load_config(path)
        assert config.targets[0].id == "t1"

    def test_missing_file_raises_config_error(self, tmp_path) -> None:
        with pytest.raises(ConfigValidationError, match="not found"):
            load_config(tmp_path / "does_not_exist.yaml")

    def test_directory_path_raises_config_error(self, tmp_path) -> None:
        with pytest.raises(ConfigValidationError, match="not a file"):
            load_config(tmp_path)

    def test_quickstart_example_loads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
        example_path = (
            __import__("pathlib").Path(__file__).resolve().parents[2] / "examples" / "quickstart.yaml"
        )
        config = load_config(example_path)
        assert config.name == "Quickstart Prompt Injection Suite"
        assert len(config.targets) == 2
        assert len(config.tests) == 1
