# Changelog

All notable changes to this project are documented in this file.

## [0.3.0] - Phase 3: 3-Tier Cascade Evaluation Pipeline

### Added

- `Verdict` enum (`PASS`/`FAIL`/`UNCERTAIN`), `EvaluationOutcome`, and the
  `BaseEvaluator` abstract interface (`cyberjection/evaluators/base.py`)
  shared by every evaluation tier.
- A pure-Python Aho-Corasick automaton
  (`cyberjection/evaluators/ahocorasick.py`) for multi-pattern substring
  matching: refusal-phrase detection costs one linear pass over the
  response regardless of how many phrases are registered, instead of one
  pass per phrase.
- `RegexEvaluator` (Tier 1, `cyberjection/evaluators/regex.py`):
  Aho-Corasick-matched refusal phrases plus compiled regexes for
  secrets/canaries (AWS access keys, JWTs, private key headers, Postgres/
  MongoDB connection strings, Slack tokens, system canary tokens). Curated
  pattern lists live in `cyberjection/evaluators/regexes/`, with built-in
  fallback defaults if the pattern files aren't present in a given install.
- `LocalONNXGuardEvaluator` (Tier 2, `cyberjection/evaluators/llamaguard.py`):
  local safety classifier. Loads a real `onnxruntime.InferenceSession` when
  a model path is given and the package is installed; otherwise falls back
  to a deterministic mock classifier (injectable via `classifier_fn`) so
  Tier 2's short-circuit and escalation paths are both testable without a
  model file.
- `LLMJudgeEvaluator` (Tier 3, `cyberjection/evaluators/llmjudge.py`):
  structured-JSON LLM-as-a-judge via `litellm.acompletion`, parsed into
  `StructuredJudgeResponse`. Supports a customizable grading rubric and
  retries transient failures (malformed JSON, empty responses, transport
  errors) with exponential backoff before falling back to `UNCERTAIN`.
- `CascadeEvaluator` (`cyberjection/evaluators/cascade.py`): chains
  Tier 1 -> Tier 2 -> Tier 3, short-circuiting on the first non-`UNCERTAIN`
  verdict. `tiers_invoked_for(outcome)` derives which tiers ran from the
  returned outcome, for cost/telemetry reporting.
- Unit test suite covering the Aho-Corasick automaton (a textbook
  overlapping-match case plus a 200-trial brute-force cross-check against
  naive substring search), all three tiers, and cascade escalation
  including zero-external-call verification on Tier 1 matches and
  correctness under concurrent `evaluate()` calls on a shared
  `CascadeEvaluator` instance.

### Fixed

- An early draft of `CascadeEvaluator` tracked which tiers ran on the most
  recent call as a `self.last_tiers_invoked` instance attribute, written
  during `evaluate()`. `CascadeEvaluator` is meant to be shared and called
  concurrently (one instance per campaign, many in-flight evaluations), and
  that attribute is exactly the kind of state that gets silently clobbered
  by a second concurrent call before the first caller reads it. Caught via
  a concurrency stress test before it shipped. Fixed by removing the
  mutable attribute entirely -- `tiers_invoked_for(outcome)` derives the
  same information from `judge_tier_used` alone, which is race-free by
  construction since it's part of the value already returned to the
  correct caller.
- `RegexEvaluator`'s optional `pattern_dir` override was implemented via
  `global _REGEXES_DIR` inside `__init__`, which would have made one
  instance's custom pattern directory leak into every `RegexEvaluator`
  constructed afterward (including default-constructed ones in unrelated
  code). Fixed before it shipped by threading `pattern_dir` through as a
  local argument instead of mutating module state.

### Known limitations

- Tier 1's sub-millisecond target holds for typical chat-turn-sized
  responses (measured well under 1ms up to ~2KB); cost scales linearly
  with response length for longer text. No included pattern uses a
  catastrophic-backtracking-prone construct (verified by adversarial-input
  timing tests), so this is a throughput characteristic, not a correctness
  or denial-of-service concern.
- `LocalONNXGuardEvaluator`'s real ONNX inference path
  (`_onnx_classify`) is an integration stub: the exact tokenization and
  output-logit layout depend on the specific quantized Llama Guard 3 export
  in use, so it raises `NotImplementedError` and directs callers to supply
  `classifier_fn` until a specific model export is wired up.
- `AssertionConfig` (Phase 1 schema: `judge_model`, `rubric`,
  `confidence_threshold`) is not yet wired to automatically construct a
  `CascadeEvaluator` from campaign YAML; that wiring is orchestrator work
  reserved for a later phase. `CascadeEvaluator` and its tiers are
  constructed directly in Python for now.

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
