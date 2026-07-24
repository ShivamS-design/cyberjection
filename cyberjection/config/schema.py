"""Pydantic v2 configuration schemas for Cyberjection campaign definitions.

These models are the single source of truth for the declarative YAML
campaign format. Every field is strongly typed and validated at load time
(see :mod:`cyberjection.config.loader`) so that malformed configuration
fails fast with a descriptive error rather than surfacing as a runtime
exception mid-campaign.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, SecretStr, model_validator


class ProviderType(str, Enum):
    """Supported target model providers, routed through the LiteLLM gateway."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    BEDROCK = "bedrock"
    AZURE = "azure"
    GEMINI = "gemini"
    VLLM = "vllm"
    CUSTOM_HTTP = "custom_http"


class AssertionType(str, Enum):
    """Evaluation assertion types applied to a target's response."""

    CONTAINS_NONE = "contains-none"
    CONTAINS_ANY = "contains-any"
    REGEX = "regex"
    LLM_JUDGE = "llm-judge"


class RateLimitConfig(BaseModel):
    """Per-target concurrency and throughput guard rails."""

    requests_per_second: int = Field(default=10, ge=1)
    burst: int = Field(default=20, ge=1)


class QualityGateConfig(BaseModel):
    """CI/CD quality-gate threshold for a campaign (Phase 6).

    The Phase 6 design spec's Task 6.5 sketches this as a flat top-level
    `cyberjection/config.py` module, which does not exist in this
    codebase -- configuration is the `cyberjection.config` package
    (`schema.py` + `loader.py`) established in Phase 1. Declared here
    instead, as an optional section of `CampaignConfig`, so a threshold
    can travel with a campaign's version-controlled YAML the same way
    `RateLimitConfig` and `StrategyConfig` already do; the CLI's
    `--threshold` flag still overrides it per invocation (see
    `cyberjection.reporting.quality_gate.resolve_threshold`).
    """

    threshold: float = Field(
        default=7.0,
        ge=0.0,
        le=10.0,
        description="Findings scoring at or above this value fail the quality gate.",
    )


class TargetConfig(BaseModel):
    """A single system-under-test endpoint (model, agent, or RAG pipeline)."""

    id: str = Field(..., description="Unique identification key for target endpoint")
    provider: ProviderType
    model: str = Field(..., description="Target model name, e.g., 'gpt-4o' or 'llama3'")
    api_key: Optional[SecretStr] = None
    api_base: Optional[str] = None
    system_prompt: Optional[str] = None
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1024, ge=1)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    custom_headers: Dict[str, str] = Field(default_factory=dict)


class StrategyConfig(BaseModel):
    """An attack strategy definition (single-turn or adaptive multi-turn).

    Full strategy execution ships in later phases; Phase 1 only needs the
    schema to exist so campaign files validate end-to-end and target/strategy
    cross-references can be checked before any network call is made.
    """

    id: str
    type: str = Field(..., description="Strategy type e.g., 'single_turn' or 'crescendo'")
    converters: List[str] = Field(default_factory=list)
    max_turns: int = Field(default=1, ge=1, le=25)
    attacker_model: Optional[str] = None


class AssertionConfig(BaseModel):
    """A pass/fail check applied against a target's response."""

    type: AssertionType
    values: Optional[List[str]] = None
    pattern: Optional[str] = None
    judge_model: Optional[str] = "openai/gpt-4o"
    rubric: Optional[str] = None
    confidence_threshold: float = Field(default=0.9, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_required_fields(self) -> "AssertionConfig":
        if self.type in (AssertionType.CONTAINS_NONE, AssertionType.CONTAINS_ANY) and not self.values:
            raise ValueError(f"Assertion type '{self.type.value}' requires a non-empty 'values' list.")
        if self.type == AssertionType.REGEX and not self.pattern:
            raise ValueError("Assertion type 'regex' requires a 'pattern'.")
        return self


class TestCaseConfig(BaseModel):
    """A single declarative test case binding a target, strategy, and assertions."""

    name: str
    target: str = Field(..., description="References a TargetConfig.id")
    strategy: str = Field(..., description="References a StrategyConfig.id")
    seed_prompt: str
    owasp_category: Optional[str] = None
    assertions: List[AssertionConfig] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CampaignConfig(BaseModel):
    """Top-level declarative campaign configuration (root of a YAML file)."""

    version: str = Field(default="1.0")
    name: str
    description: Optional[str] = None
    targets: List[TargetConfig]
    strategies: List[StrategyConfig] = Field(default_factory=list)
    tests: List[TestCaseConfig] = Field(default_factory=list)
    max_cost_cap: float = Field(default=10.0, ge=0.0)
    max_workers: int = Field(default=50, ge=1, le=200)
    quality_gate: QualityGateConfig = Field(default_factory=QualityGateConfig)

    @model_validator(mode="after")
    def validate_unique_target_ids(self) -> "CampaignConfig":
        target_ids = [t.id for t in self.targets]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("Target IDs within a campaign configuration must be unique.")
        return self

    @model_validator(mode="after")
    def validate_unique_strategy_ids(self) -> "CampaignConfig":
        strategy_ids = [s.id for s in self.strategies]
        if len(strategy_ids) != len(set(strategy_ids)):
            raise ValueError("Strategy IDs within a campaign configuration must be unique.")
        return self

    @model_validator(mode="after")
    def validate_cross_references(self) -> "CampaignConfig":
        target_ids = {t.id for t in self.targets}
        strategy_ids = {s.id for s in self.strategies}
        for test in self.tests:
            if test.target not in target_ids:
                raise ValueError(
                    f"Test '{test.name}' references unknown target id '{test.target}'. "
                    f"Known target ids: {sorted(target_ids)}"
                )
            if strategy_ids and test.strategy not in strategy_ids:
                raise ValueError(
                    f"Test '{test.name}' references unknown strategy id '{test.strategy}'. "
                    f"Known strategy ids: {sorted(strategy_ids)}"
                )
        return self
