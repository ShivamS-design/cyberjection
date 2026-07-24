# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - Phase 2: Mutation Engine & Single-Turn Attack Generators

### Added

- `BaseMutator` abstract interface and `MutatorPipeline` chaining engine
  (`cyberjection/mutators/base.py`): mutators are applied strictly in list
  order, each consuming the previous mutator's output.
- Dynamic mutator registry (`cyberjection/mutators/registry.py`):
  `register_mutator`, `get_mutator`, `list_mutator_aliases`,
  `build_pipeline`, so mutator chains can be declared as plain alias
  strings (e.g. in `StrategyConfig.converters`) instead of importing
  concrete classes. Registering a different class under an alias already
  in use raises `MutatorRegistrationError` rather than silently shadowing
  it; re-registering the same class is idempotent.
- Five concrete mutators, each registered under a short alias:
  `Base64Mutator` (`base64`), `HomoglyphMutator` (`homoglyph`),
  `UnicodeZeroWidthMutator` (`unicode_zero_width`), `TypoglycemiaMutator`
  (`typoglycemia`), and `ROT13Mutator` / `CaesarCipherMutator` (`rot13`).
- `BaseStrategy` abstract interface, `ExecutionContext`, and
  `SingleTurnResult` (`cyberjection/attacks/base.py`), including a shared
  `_apply_mutations` pre-hook so every strategy runs its configured
  mutator pipeline the same way before dispatch.
- Three single-turn attack strategies built on the Phase 1 target gateway:
  `DirectPromptInjectionStrategy` (override framing),
  `JailbreakStrategy` (persona/roleplay framing: Developer Mode, DAN-style,
  sandboxed VM simulation), and `SystemPromptExtractionStrategy`
  (system-prompt / context-window leak probes).
- Unit test suite covering every mutator's transformation logic, the
  registry's registration/collision/lookup behavior, pipeline chaining and
  ordering, and each attack strategy executed against a mocked
  `LiteLLMTarget`.

### Fixed

- The zero-width-space and typoglycemia mutators originally drew from the
  shared global `random` module. Phase 2's stated objective requires
  "deterministic string transformers," but unseeded global-random calls
  make generated payloads impossible to reproduce or replay for
  evaluation, and mutate shared process-wide random state as a side
  effect. Fixed by giving every randomized mutator an optional `seed`
  parameter backed by a private `random.Random` instance: the same seed
  now reproduces byte-identical output, and seeding one mutator never
  perturbs another's random sequence.

### Known limitations

- `StrategyConfig.converters` (Phase 1 schema) is not yet wired to
  automatically build a `MutatorPipeline` at campaign-load time; callers
  currently construct a pipeline explicitly via
  `cyberjection.mutators.build_pipeline` and pass it to a strategy.
  Automatic wiring lands with the orchestrator in a later phase.
- Chaining `base64` with a character-level mutator that runs *after* it
  (homoglyph, zero-width, typoglycemia) corrupts the Base64 encoding by
  design -- these mutators operate on raw characters with no awareness of
  an upstream encoding step. See `docs/ARCHITECTURE.md#mutator-chaining-and-ordering`.
- The cascade evaluator, persistence, the CLI, the REST API, the
  dashboard, and reporting are not implemented yet; they ship in
  Phases 3-10 (see `docs/ARCHITECTURE.md`).

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
