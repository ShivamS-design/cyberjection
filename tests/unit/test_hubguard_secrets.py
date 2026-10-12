"""Tests for cyberjection.hubguard.secrets.

Credential-shaped fixtures are assembled from fragments at runtime so this
test file itself doesn't trip secret scanners (including this project's
own `cyberjection audit --secrets`).
"""

from __future__ import annotations

import pytest

from cyberjection.hubguard.models import Severity
from cyberjection.hubguard.secrets import find_secrets, is_text_candidate, scan_text_for_leaks

ALNUM = "Q7mZp2Lk9VxR4tBn8WcY3hJd6FsG1aEu0oKiNqPl"


def j(*parts: str) -> str:
    return "".join(parts)


CASES = [
    ("huggingface_token", j("hf", "_", ALNUM[:34])),
    ("anthropic_api_key", j("sk-ant-", "api03-", (ALNUM * 3)[:90])),
    ("openai_api_key", j("sk-", "proj-", (ALNUM * 2)[:56])),
    ("aws_access_key_id", j("AK", "IA", "Z7Q3M9X2R5T8W1Y4")),
    ("google_api_key", j("AI", "za", (ALNUM + "_-")[:35])),
    ("github_token", j("gh", "p_", (ALNUM * 2)[:36])),
    ("gitlab_token", j("gl", "pat-", ALNUM[:20])),
    ("slack_token", j("xo", "xb-", "1234567890-abcdefghijk")),
    ("stripe_live_key", j("sk", "_live_", ALNUM[:24])),
    ("replicate_token", j("r8", "_", ALNUM[:37])),
    ("private_key", j("-----BEGIN ", "OPENSSH PRIVATE KEY-----")),
    ("database_url", j("postgres", "ql://admin:", "Tr0ub4dor9xq", "@db.prod.acme.io:5432/models")),
    ("slack_webhook", j("https://hooks.slack", ".com/services/", "T0ABCDEF/B0ABCDEF/", ALNUM[:24])),
    ("discord_webhook", j("https://discord", ".com/api/webhooks/", "123456789012/", ALNUM)),
    ("wandb_api_key", j("WANDB_API_KEY=", "3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c8e2b4d6f19")),
    ("azure_storage_key", j("DefaultEndpointsProtocol=https;AccountName=x;AccountKey=", (ALNUM * 3)[:88])),
    ("internal_url", "see http://mlflow.corp:5000/run/7 for metrics"),
]


class TestDetection:
    @pytest.mark.parametrize("rule,text", CASES)
    def test_detects(self, rule: str, text: str) -> None:
        matches = find_secrets(f"usage: {text}\n")
        assert rule in {m.rule for m in matches}, matches

    @pytest.mark.parametrize("rule,text", CASES)
    def test_never_echoes_secret(self, rule: str, text: str) -> None:
        for finding in scan_text_for_leaks(text, source="README.md"):
            assert len(text) <= 8 or text not in (finding.evidence or "")
            assert text not in finding.description

    def test_generic_high_entropy_assignment(self) -> None:
        matches = find_secrets(j('"api_key": "', "Zx81Lq0", 'pW3vR7tK2mN9bY5c"'))
        assert [m.rule for m in matches] == ["generic_secret_assignment"]
        assert matches[0].severity == Severity.MEDIUM

    def test_specific_rule_wins_over_generic(self) -> None:
        token = j("hf", "_", ALNUM[:34])
        rules = [m.rule for m in find_secrets(f'token = "{token}"')]
        assert rules == ["huggingface_token"]

    def test_line_numbers(self) -> None:
        text = "line one\nline two\n" + j("hf", "_", ALNUM[:34]) + "\n"
        assert find_secrets(text)[0].line == 3


class TestPlaceholders:
    @pytest.mark.parametrize(
        "text",
        [
            "HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            'api_key = "<your-api-key-here-please>"',
            'api_key = "${OPENAI_API_KEY_FROM_ENV}"',
            "postgres://user:password@localhost:5432/db",
            'token: "aaaaaaaaaaaaaaaaaaaaaaaa"',
            'password = "short"',
            "token = YOUR_TOKEN_HERE_ABCDEFGHIJ",
            "Use model.generate(max_new_tokens=200) to sample.",
            "https://huggingface.co/meta-llama/Llama-3-8B",
        ],
    )
    def test_not_flagged(self, text: str) -> None:
        assert find_secrets(text) == []

    def test_example_word_on_line_does_not_hide_real_key(self) -> None:
        # The Phase 8 scanner skips whole lines mentioning "example"; this
        # one judges the matched value, so a real key on such a line is found.
        text = "For example: " + j("hf", "_", ALNUM[:34])
        assert [m.rule for m in find_secrets(text)] == ["huggingface_token"]


class TestFindings:
    def test_finding_shape(self) -> None:
        findings = scan_text_for_leaks(j("hf", "_", ALNUM[:34]), source="README.md", context="historical revision abc")
        f = findings[0]
        assert f.rule_id == "secrets.huggingface_token"
        assert f.file == "README.md" and f.line == 1
        assert "historical revision abc" in f.description
        assert "rotate" in (f.remediation or "")

    @pytest.mark.parametrize(
        "path,size,expected",
        [
            ("README.md", 100, True),
            ("config.json", 100, True),
            (".env", 10, True),
            (".env.production", 10, True),
            ("model.safetensors", 100, False),
            ("README.md", 50_000_000, False),
            ("notebooks/train.ipynb", 1000, True),
        ],
    )
    def test_is_text_candidate(self, path: str, size: int, expected: bool) -> None:
        assert is_text_candidate(path, size) is expected
