"""Tests for cyberjection.config.schema: Pydantic v2 model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cyberjection.config.schema import (
    AssertionConfig,
    AssertionType,
    CampaignConfig,
    ProviderType,
    RateLimitConfig,
    StrategyConfig,
    TargetConfig,
    TestCaseConfig,
)


def _target(id_: str = "t1", **overrides) -> TargetConfig:
    defaults = dict(id=id_, provider=ProviderType.OPENAI, model="gpt-4o-mini")
    defaults.update(overrides)
    return TargetConfig(**defaults)


class TestTargetConfig:
    def test_valid_target(self) -> None:
        target = _target()
        assert target.provider == ProviderType.OPENAI
        assert target.temperature == 0.0
        assert isinstance(target.rate_limit, RateLimitConfig)

    def test_temperature_out_of_range_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _target(temperature=2.5)

    def test_negative_max_tokens_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _target(max_tokens=0)

    def test_invalid_provider_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TargetConfig(id="t1", provider="not-a-real-provider", model="x")

    def test_api_key_is_secret(self) -> None:
        target = _target(api_key="sk-super-secret")
        assert "sk-super-secret" not in repr(target)
        assert target.api_key.get_secret_value() == "sk-super-secret"


class TestStrategyConfig:
    def test_valid_strategy(self) -> None:
        strategy = StrategyConfig(id="s1", type="crescendo", max_turns=5)
        assert strategy.max_turns == 5

    def test_max_turns_upper_bound_enforced(self) -> None:
        with pytest.raises(ValidationError):
            StrategyConfig(id="s1", type="crescendo", max_turns=26)

    def test_max_turns_lower_bound_enforced(self) -> None:
        with pytest.raises(ValidationError):
            StrategyConfig(id="s1", type="crescendo", max_turns=0)


class TestAssertionConfig:
    def test_contains_none_requires_values(self) -> None:
        with pytest.raises(ValidationError, match="values"):
            AssertionConfig(type=AssertionType.CONTAINS_NONE)

    def test_regex_requires_pattern(self) -> None:
        with pytest.raises(ValidationError, match="pattern"):
            AssertionConfig(type=AssertionType.REGEX)

    def test_llm_judge_requires_no_extra_fields(self) -> None:
        assertion = AssertionConfig(type=AssertionType.LLM_JUDGE, rubric="Score fairly.")
        assert assertion.confidence_threshold == 0.9

    def test_valid_contains_any(self) -> None:
        assertion = AssertionConfig(type=AssertionType.CONTAINS_ANY, values=["a", "b"])
        assert assertion.values == ["a", "b"]


class TestCampaignConfig:
    def test_valid_minimal_campaign(self) -> None:
        campaign = CampaignConfig(name="C1", targets=[_target()])
        assert campaign.max_cost_cap == 10.0
        assert campaign.max_workers == 50

    def test_duplicate_target_ids_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unique"):
            CampaignConfig(name="C1", targets=[_target("dup"), _target("dup")])

    def test_duplicate_strategy_ids_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unique"):
            CampaignConfig(
                name="C1",
                targets=[_target()],
                strategies=[
                    StrategyConfig(id="dup", type="single_turn"),
                    StrategyConfig(id="dup", type="single_turn"),
                ],
            )

    def test_negative_cost_cap_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CampaignConfig(name="C1", targets=[_target()], max_cost_cap=-1.0)

    def test_test_case_referencing_unknown_target_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown target"):
            CampaignConfig(
                name="C1",
                targets=[_target("t1")],
                strategies=[StrategyConfig(id="s1", type="single_turn")],
                tests=[
                    TestCaseConfig(
                        name="test-a",
                        target="does-not-exist",
                        strategy="s1",
                        seed_prompt="hi",
                    )
                ],
            )

    def test_test_case_referencing_unknown_strategy_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown strategy"):
            CampaignConfig(
                name="C1",
                targets=[_target("t1")],
                strategies=[StrategyConfig(id="s1", type="single_turn")],
                tests=[
                    TestCaseConfig(
                        name="test-a",
                        target="t1",
                        strategy="does-not-exist",
                        seed_prompt="hi",
                    )
                ],
            )

    def test_test_case_with_valid_references_accepted(self) -> None:
        campaign = CampaignConfig(
            name="C1",
            targets=[_target("t1")],
            strategies=[StrategyConfig(id="s1", type="single_turn")],
            tests=[
                TestCaseConfig(name="test-a", target="t1", strategy="s1", seed_prompt="hi"),
            ],
        )
        assert campaign.tests[0].name == "test-a"

    def test_max_workers_bounds(self) -> None:
        with pytest.raises(ValidationError):
            CampaignConfig(name="C1", targets=[_target()], max_workers=0)
        with pytest.raises(ValidationError):
            CampaignConfig(name="C1", targets=[_target()], max_workers=500)


class TestMutableDefaults:
    """Regression coverage: Field(default_factory=...) must produce an
    independent object per instance. Using a shared `default=` instance
    instead would leak mutable state (e.g. custom_headers) across every
    TargetConfig created without an explicit value -- a classic Python
    mutable-default-argument bug re-appearing at the schema layer."""

    def test_custom_headers_not_shared_between_instances(self) -> None:
        t1 = _target("a")
        t2 = _target("b")
        t1.custom_headers["X-Injected"] = "leaked"
        assert "X-Injected" not in t2.custom_headers

    def test_rate_limit_default_not_shared_between_instances(self) -> None:
        t1 = _target("a")
        t2 = _target("b")
        t1.rate_limit.burst = 999
        assert t2.rate_limit.burst == 20

    def test_converters_list_not_shared_between_instances(self) -> None:
        s1 = StrategyConfig(id="s1", type="single_turn")
        s2 = StrategyConfig(id="s2", type="single_turn")
        s1.converters.append("base64")
        assert s2.converters == []
