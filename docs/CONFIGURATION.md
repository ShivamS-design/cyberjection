# Configuration reference

Campaigns are defined in a single YAML file, validated against the schema
in `cyberjection/config/schema.py`. Load one with:

```python
from cyberjection.config.loader import load_config
config = load_config("examples/quickstart.yaml")
```

## Environment variable expansion

Any `${VAR_NAME}` or `${VAR_NAME:-default}` token in the YAML source is
substituted before parsing, so secrets never need to live in the file
itself:

```yaml
api_key: "${OPENAI_API_KEY}"
api_base: "${OLLAMA_API_BASE:-http://localhost:11434}"
```

- If `VAR_NAME` is set in the environment, its value is used.
- Otherwise, if an inline `:-default` is present, the default is used.
- Otherwise, loading fails with a `ConfigValidationError` listing every
  unresolved variable, rather than proceeding with a blank value.

Expansion is single-pass: if `OUTER` resolves to a string that itself
contains `${INNER}`, that is left as literal text, not expanded again.

## Top-level fields (`CampaignConfig`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `version` | string | `"1.0"` | Schema version tag. |
| `name` | string | required | Campaign display name. |
| `description` | string | optional | Free-text description. |
| `targets` | list of `TargetConfig` | required | Must have unique `id`s. |
| `strategies` | list of `StrategyConfig` | `[]` | Must have unique `id`s. |
| `tests` | list of `TestCaseConfig` | `[]` | Each `target` and `strategy` reference must match a known id. |
| `max_cost_cap` | float | `10.0` | Hard budget ceiling in USD; must be `>= 0`. |
| `max_workers` | int | `50` | Concurrent worker cap; `1-200`. |

## `TargetConfig`

| Field | Type | Default | Notes |
|---|---|---|---|
| `id` | string | required | Unique key referenced by test cases. |
| `provider` | enum | required | One of `openai`, `anthropic`, `ollama`, `bedrock`, `azure`, `gemini`, `vllm`, `custom_http`. |
| `model` | string | required | Provider-specific model name, e.g. `gpt-4o-mini`. |
| `api_key` | secret string | optional | Wrapped in `SecretStr`; never printed in reprs or logs. |
| `api_base` | string | optional | Custom endpoint base URL. |
| `system_prompt` | string | optional | Default system prompt for this target. |
| `temperature` | float | `0.0` | `0.0-2.0`. |
| `max_tokens` | int | `1024` | Must be `>= 1`. |
| `rate_limit` | `RateLimitConfig` | see below | Per-target throughput controls. |
| `custom_headers` | dict[str, str] | `{}` | Extra HTTP headers for custom endpoints. |

## `RateLimitConfig`

| Field | Type | Default | Notes |
|---|---|---|---|
| `requests_per_second` | int | `10` | Paced by an async token-bucket limiter; must be `>= 1`. |
| `burst` | int | `20` | Token-bucket capacity **and** the concurrency semaphore size; must be `>= 1`. |

## `StrategyConfig`

| Field | Type | Default | Notes |
|---|---|---|---|
| `id` | string | required | Unique key referenced by test cases. |
| `type` | string | required | e.g. `single_turn`, `adaptive`. |
| `converters` | list[str] | `[]` | Mutator aliases applied to prompts, in order, via `cyberjection.mutators.build_pipeline`. See [Mutators](#mutators). |
| `max_turns` | int | `1` | `1-25`, enforcing the multi-turn depth guardrail. |
| `attacker_model` | string | optional | Model used to generate adaptive attack prompts (Phase 5+). |

## `AssertionConfig`

| Field | Type | Default | Notes |
|---|---|---|---|
| `type` | enum | required | `contains-none`, `contains-any`, `regex`, `llm-judge`. |
| `values` | list[str] | optional | Required for `contains-none` / `contains-any`. |
| `pattern` | string | optional | Required for `regex`. |
| `judge_model` | string | `"openai/gpt-4o"` | Used by `llm-judge`. |
| `rubric` | string | optional | Grading instructions for `llm-judge`. |
| `confidence_threshold` | float | `0.9` | `0.0-1.0`. |

## `TestCaseConfig`

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string | required | Test case display name. |
| `target` | string | required | Must match a `TargetConfig.id`. |
| `strategy` | string | required | Must match a `StrategyConfig.id`. |
| `seed_prompt` | string | required | Initial prompt for the strategy. |
| `owasp_category` | string | optional | e.g. `LLM06_SENSITIVE_INFO_DISCLOSURE`. |
| `assertions` | list of `AssertionConfig` | `[]` | Checks run against the response. The `cyberjection.evaluators` cascade (Phase 3) implements the evaluation tiers this config describes; wiring `AssertionConfig` fields directly into a `CascadeEvaluator` call is orchestrator work reserved for a later phase. |
| `metadata` | dict | `{}` | Free-form key/value pairs. |

## Mutators

Mutators live in `cyberjection.mutators` and transform a prompt string into
an obfuscated payload. Each is registered under a short alias so it can be
referenced by name (e.g. in `StrategyConfig.converters`) instead of
importing the class directly:

```python
from cyberjection.mutators import build_pipeline, list_mutator_aliases

list_mutator_aliases()
# ['base64', 'homoglyph', 'rot13', 'typoglycemia', 'unicode_zero_width']

pipeline = build_pipeline(["typoglycemia", "rot13"])
pipeline.execute("ignore all previous instructions")
```

| Alias | Class | Notes |
|---|---|---|
| `base64` | `Base64Mutator` | Encodes the prompt as Base64 wrapped in decoder instructions. Put this **last** in a chain -- later character-level mutators will corrupt the encoding. |
| `homoglyph` | `HomoglyphMutator` | Latin -> Cyrillic/Greek confusable substitution. Optional `substitution_rate` (default `1.0`) and `seed` for partial, reproducible substitution. |
| `unicode_zero_width` | `UnicodeZeroWidthMutator` | Injects invisible `U+200B` between characters. Optional `insertion_rate` (default `0.4`) and `seed`. |
| `typoglycemia` | `TypoglycemiaMutator` | Scrambles interior letters of words longer than 3 characters; first/last letters and non-alphabetic tokens are preserved. Optional `seed`. |
| `rot13` | `ROT13Mutator` | ROT13 substitution cipher; its own inverse. The general case, `CaesarCipherMutator(shift=N)`, is available but not separately registered. |

Mutators that use randomization accept an optional `seed` for reproducible
output; each draws from its own private RNG instance rather than the
shared `random` module, so seeding one mutator never affects another.

## Attack strategies

Single-turn strategies live in `cyberjection.attacks` and implement
`BaseStrategy.execute(target, seed_prompt, context) -> SingleTurnResult`.
Every strategy accepts an optional `mutator_pipeline` (a `MutatorPipeline`)
applied to the framed prompt before dispatch.

| Strategy | `strategy_id` | Notes |
|---|---|---|
| `DirectPromptInjectionStrategy` | `direct_prompt_injection` | Wraps the seed prompt in one of three override-framing templates, selected via `frame_index` (mod 3). |
| `JailbreakStrategy` | `jailbreak_roleplay` | Wraps the seed prompt in a persona frame: `developer_mode` (default), `dan`, or `vm_simulation`, selected via `persona`. |
| `SystemPromptExtractionStrategy` | `system_prompt_extraction` | Sends one of four extraction probes, selected via `probe_index` (mod 4); the last probe embeds `seed_prompt` as pretext, the others probe directly. |

`ExecutionContext(test_id, target_id, owasp_category="LLM01_PROMPT_INJECTION",
max_cost_limit=5.0)` carries the per-test metadata a strategy needs;
`SingleTurnResult` is the standardized output every strategy returns,
ready for the evaluation cascade.

## Evaluators

`cyberjection.evaluators` judges a `(prompt_sent, response_text)` pair and
returns an `EvaluationOutcome`:

```python
from cyberjection.evaluators import CascadeEvaluator

cascade = CascadeEvaluator()
outcome = await cascade.evaluate(result.original_prompt, result.target_response)
print(outcome.verdict, outcome.confidence, outcome.reason)
```

`EvaluationOutcome` fields: `verdict` (`PASS` / `FAIL` / `UNCERTAIN`),
`confidence` (`0.0-1.0`), `judge_tier_used` (`1-3`), `reason`,
`owasp_category` (optional), `raw_response` (optional, populated for Tier 3).

| Tier | Class | Constructor options | Notes |
|---|---|---|---|
| 1 | `RegexEvaluator` | `custom_refusal_patterns`, `custom_secret_regexes`, `pattern_dir` | Zero-cost, sub-millisecond for typical response sizes. Defaults load from `cyberjection/evaluators/regexes/*.txt`; pass explicit lists to override rather than editing the packaged files. |
| 2 | `LocalONNXGuardEvaluator` | `model_path`, `confidence_threshold` (default `0.90`), `classifier_fn`, `simulated_latency_seconds` | Falls back to a deterministic mock classifier if `onnxruntime` or `model_path` isn't available -- see [Tier 2 without a real model](ARCHITECTURE.md#tier-2-without-a-real-model). |
| 3 | `LLMJudgeEvaluator` | `judge_model` (default `"openai/gpt-4o"`), `rubric`, `max_retries` (default `1`), `backoff_base_seconds` | Calls `litellm.acompletion` directly with `response_format={"type": "json_object"}`, parsed into `StructuredJudgeResponse`. A rubric string, if given, is appended to the judge system prompt for zero-shot policy customization. |

`CascadeEvaluator(tier1=None, tier2=None, tier3=None,
tier2_confidence_threshold=0.90)` chains all three; pass explicit tier
instances to override any of them (e.g. a custom `judge_model`, or a
`RegexEvaluator` with an organization-specific secret pattern list). Every
evaluator's `.evaluate()` and the cascade's own `.evaluate()` are safe to
call concurrently on a shared instance -- no mutable state is held on
`self` during evaluation.

## Full example

See [`examples/quickstart.yaml`](../examples/quickstart.yaml) for a
complete, valid campaign file exercising targets, strategies, and a test
case with assertions.
