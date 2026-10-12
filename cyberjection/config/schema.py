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
    HUGGINGFACE = "huggingface"


class AssertionType(str, Enum):
    """Evaluation assertion types applied to a target's response."""

    CONTAINS_NONE = "contains-none"
    CONTAINS_ANY = "contains-any"
    REGEX = "regex"
    LLM_JUDGE = "llm-judge"


class PricingConfig(BaseModel):
    """Explicit per-token pricing for a target LiteLLM can't price itself
    (self-hosted, fine-tuned or custom endpoints). Used by
    `cyberjection.budget` to enforce `max_cost_cap`."""

    input_per_million_usd: float = Field(..., ge=0.0, description="USD per 1M prompt tokens.")
    output_per_million_usd: float = Field(..., ge=0.0, description="USD per 1M completion tokens.")


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


class HubGuardConfig(BaseModel):
    """Phase 11 model supply-chain gate, applied to every `huggingface`
    target before a campaign sends it a single prompt (see
    `cyberjection.hubguard.gate`). Declaring the section turns the gate on;
    omitting it leaves campaigns exactly as they behaved before Phase 11."""

    enforce_safetensors: bool = Field(
        default=True, description="STRICT SafeTensors-only policy; False downgrades pickle weights to warnings."
    )
    block_remote_code: bool = Field(
        default=True, description="Reject repositories (and targets) that need trust_remote_code=True."
    )
    max_allowed_risk_score: float = Field(default=7.0, ge=0.0, le=10.0)
    allowed_organizations: List[str] = Field(
        default_factory=list, description="Hub organizations targets may come from; empty allows any."
    )
    scan_pickles: bool = True
    scan_remote_code: bool = True
    scan_secrets: bool = True
    history_depth: int = Field(default=10, ge=0, le=200)
    manifest: Optional[str] = Field(default=None, description="Path to a SHA-256 HashManifest (YAML/JSON).")
    verify_downloads: bool = False
    profile_remote_code: bool = Field(
        default=False, description="Opt-in: execute remote code in the restricted sandbox profiler."
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
    pricing: Optional[PricingConfig] = Field(
        default=None, description="Override LiteLLM's pricing data for budget enforcement."
    )
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    trust_remote_code: bool = Field(
        default=False, description="Whether this (Hugging Face) target is loaded with trust_remote_code=True."
    )
    revision: Optional[str] = Field(
        default=None, description="Hub revision (branch, tag or commit SHA) HubGuard audits; defaults to 'main'."
    )


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
    max_cost_cap: float = Field(
        default=10.0,
        ge=0.0,
        description="USD cap on measured model spend (target, attacker and judge calls); 0 disables it.",
    )
    max_workers: int = Field(default=50, ge=1, le=200)
    quality_gate: QualityGateConfig = Field(default_factory=QualityGateConfig)
    hubguard: Optional[HubGuardConfig] = None

    @model_validator(mode="after")
    def validate_hubguard_policy(self) -> "CampaignConfig":
        """Fails fast at load time on policy violations that need no network
        access: remote code a policy forbids, or an organization outside the
        allowlist. Repository-content checks happen in the gate itself."""

        if self.hubguard is None:
            return self
        allowed = {o.lower() for o in self.hubguard.allowed_organizations}
        for target in self.targets:
            if self.hubguard.block_remote_code and target.trust_remote_code:
                raise ValueError(
                    f"Target '{target.id}' sets trust_remote_code: true but hubguard.block_remote_code is enabled."
                )
            if target.provider != ProviderType.HUGGINGFACE:
                continue
            from cyberjection.hubguard.transport import repo_id_from_model

            try:
                repo_id = repo_id_from_model(target.model)
            except ValueError as exc:
                raise ValueError(f"Target '{target.id}': {exc}") from None
            org = repo_id.split("/")[0].lower() if "/" in repo_id else ""
            if allowed and org not in allowed:
                raise ValueError(
                    f"Target '{target.id}' model '{repo_id}' is from organization '{org or '(none)'}', "
                    f"which is not in hubguard.allowed_organizations {sorted(allowed)}."
                )
        return self

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
