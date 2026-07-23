# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - Phase 1: Core Async Architecture, Declarative Configuration & Target Abstraction Gateway

### Added

- YAML campaign configuration loader with `${VAR}` / `${VAR:-default}`
  environment-variable expansion (`cyberjection/config/loader.py`).
  Expansion is single-pass by design: a value that itself contains `${VAR}`
  syntax is not re-expanded, which prevents one environment variable from
  being used to smuggle in a reference to a second, more sensitive one.
- Pydantic v2 schema for campaign configuration: `TargetConfig`,
  `StrategyConfig`, `AssertionConfig`, `TestCaseConfig`, `CampaignConfig`,
  `RateLimitConfig` (`cyberjection/config/schema.py`). Includes
  cross-reference validation so a test case referencing an unknown target
  or strategy id fails at load time with a descriptive error, not at
  runtime.
- `LiteLLMTarget`, a universal target gateway wrapping `litellm.acompletion`
  (`cyberjection/providers/litellm_provider.py`), giving uniform access to
  OpenAI, Anthropic, Bedrock, Azure, Ollama, vLLM, Gemini, and custom HTTP
  endpoints.
- Per-target rate limiting: a token-bucket limiter paces admission to the
  configured `requests_per_second`, and an `asyncio.Semaphore` caps
  concurrent in-flight requests at `burst`.
- Retry with exponential backoff for transient failures (rate limits,
  timeouts); connection errors fail fast without retrying.
- Normalized `TargetResponse` / `UsageMetrics` on every call, capturing
  content, latency, and prompt/completion token counts regardless of
  provider.
- Unified exception hierarchy (`cyberjection/utils/exceptions.py`) so
  callers only need to handle one family of errors instead of every
  provider SDK's native exception types.
- Unit test suite covering the config loader, schema validation, and the
  provider adapter under mocked and real concurrent load, including:
  - concurrency-cap enforcement (never exceeds `burst` in-flight calls)
  - semaphore release under mixed success/failure batches
  - correct propagation of `asyncio.CancelledError` through the retry path
    (cancellation must not be misclassified as a connection error)
  - rate-limit pacing verification for the token-bucket limiter
  - independence of `default_factory`-based fields (`custom_headers`,
    `converters`, `rate_limit`) across model instances

### Fixed

- `RateLimitConfig.requests_per_second` was defined in the schema but never
  read anywhere; only `burst` (via the semaphore) had any effect on request
  pacing. A fast or local target could therefore exceed its configured
  requests-per-second limit. Fixed by adding a token-bucket limiter that
  gates admission before the concurrency semaphore.

### Known limitations

- Retries within a single `generate()` call (after a rate-limit or timeout
  error) do not consume an additional rate-limit token; only the initial
  admission is bucketed. Exponential backoff between retries is coarse
  enough in practice that this rarely matters, but it is worth knowing if
  `backoff_base_seconds` is tuned very low.
- Mutators, attack strategies, the cascade evaluator, persistence, the CLI,
  the REST API, the dashboard, and reporting are not implemented yet; they
  ship in Phases 2-10 (see `docs/ARCHITECTURE.md`).
