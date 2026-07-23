"""Shared pytest fixtures for the Cyberjection test suite."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest


@pytest.fixture
def tmp_yaml_file(tmp_path: Path):
    """Factory fixture: write text to a temp .yaml file and return its path."""

    def _write(text: str, filename: str = "campaign.yaml") -> Path:
        path = tmp_path / filename
        path.write_text(text, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Ensure OPENAI_API_KEY-style vars used in tests don't leak between tests."""

    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_API_BASE"):
        monkeypatch.delenv(var, raising=False)
    yield
