# Architecture

## Overview

Cyberjection is organized as a layered, asynchronous pipeline. Configuration
flows down from the presentation layer through orchestration, the attack and
mutation engine, the target abstraction layer, evaluation, and finally
persistence and reporting.

```
 PRESENTATION LAYER
   apps/cli (Typer) | apps/api (FastAPI) | apps/dashboard (React)
          |
          v  YAML / REST API
 ORCHESTRATION LAYER
   cyberjection/orchestrator/{campaign,scheduler,worker_pool,state}.py
          |
          v  async queue / state management
 ATTACK & MUTATION ENGINE
   single-turn: direct injection, jailbreaks, roleplay, DAN
   multi-turn:  crescendo, PAIR, TAP, tree search
   mutators:    base64, homoglyph, typoglycemia, unicode, pig latin
          |
          v  normalized prompt payload
 TARGET ABSTRACTION LAYER
   cyberjection/providers/litellm_provider.py (OpenAI, Anthropic, Ollama, Bedrock, ...)
   cyberjection/providers/custom_http.py (custom REST, RAG, agent endpoints)
          |
          v  response content
 CASCADE EVALUATION PIPELINE
   tier 1: regex & substring matcher   (< 1 ms)
   tier 2: local ONNX safety model     (5-20 ms)
   tier 3: LLM-as-a-judge              (500-2000 ms)
          |
          v  evaluation verdict & findings
 PERSISTENCE & REPORTING LAYER
   SQLAlchemy 2 (SQLite / PostgreSQL) + Redis queue
   SARIF v2.1.0, interactive HTML (Jinja2), JSON, CSV
```

## Design principles

- **Async-first execution.** The engine is built natively on Python
  `asyncio`, targeting 50+ concurrent test workers without thread
  blocking. Structured concurrency (`asyncio.TaskGroup`, `asyncio.gather`)
  is preferred over unstructured task spawning so cancellation and error
  propagation stay predictable.
- **Modular strategy and mutation pipeline.** Payload generation, mutation
  (obfuscation), target transport, and response evaluation are decoupled
  stages, each independently extensible.
- **Three-tier cascade evaluation.** Judging cost is minimized by
  escalating only when necessary: deterministic regex first, a local ONNX
  safety classifier second, and a full LLM judge only for ambiguous cases.
- **Pluggable architecture.** Python entry points allow third-party attacks,
  targets, mutators, and report formats to be added without modifying core
  code.
- **Cost and safety guardrails.** Campaigns enforce a hard budget cap
  (`max_cost_cap`) and bounded conversation depth (`max_turns`, capped at
  25) to prevent runaway multi-turn loops from generating unbounded spend.

## Phase 1: Core Async Architecture & Target Abstraction Gateway

Covers the bottom two layers of the diagram above (target abstraction) plus
the configuration layer that feeds the orchestrator in later phases.

| Module | Responsibility |
|---|---|
| `cyberjection/config/schema.py` | Pydantic v2 models for the campaign YAML format: `TargetConfig`, `StrategyConfig`, `AssertionConfig`, `TestCaseConfig`, `CampaignConfig`, `RateLimitConfig`. |
| `cyberjection/config/loader.py` | Loads a YAML file or string, expands `${VAR}` tokens against the process environment, parses, and validates against the schema. |
| `cyberjection/providers/base.py` | `BaseTarget`, the abstract async interface every target adapter implements. |
| `cyberjection/providers/litellm_provider.py` | `LiteLLMTarget`: the concrete adapter wrapping `litellm.acompletion`, plus the token-bucket rate limiter and retry/backoff logic. |
| `cyberjection/utils/exceptions.py` | Unified exception hierarchy (`CyberjectionException` and subclasses) so callers handle one error family regardless of the underlying provider SDK. |
| `cyberjection/utils/context.py` | `ExecutionContext` and `StrategyResult`, the runtime structures threaded through orchestrator -> strategy -> target -> evaluator in later phases. |

### Target gateway concurrency model

Each `LiteLLMTarget` instance owns two independent limiters, both derived
from `TargetConfig.rate_limit`:

- A **token bucket** (`requests_per_second`, capacity `burst`) that paces
  *admission* -- how often a new call is allowed to start.
- An **`asyncio.Semaphore`** (sized to `burst`) that caps *concurrency* --
  how many calls may be in flight at the same instant.

A call acquires the token bucket first, then the semaphore, then executes
through `_call_with_retry`, which retries rate-limit and timeout errors
with exponential backoff while failing fast on connection errors. The
semaphore is held for the duration of all retries for a given call, which
intentionally slows further concurrent admission to the same target while
it's backing off from a rate limit.

## Phase 2: Mutation Engine & Single-Turn Attack Generators

Covers the offensive payload generation core built on top of the Phase 1
target gateway: a chainable mutation pipeline, a dynamic mutator registry,
and the first three single-turn attack strategies.

| Module | Responsibility |
|---|---|
| `cyberjection/mutators/base.py` | `BaseMutator` abstract interface and `MutatorPipeline`, the sequencing engine that chains mutators. |
| `cyberjection/mutators/registry.py` | Dynamic alias registry (`register_mutator`, `get_mutator`, `build_pipeline`) so mutator chains can be declared as plain alias strings. |
| `cyberjection/mutators/base64_mutator.py` | `Base64Mutator`: encodes the payload as Base64 wrapped in decoder instructions. |
| `cyberjection/mutators/unicode_mutator.py` | `UnicodeZeroWidthMutator` (invisible `U+200B` injection) and `HomoglyphMutator` (Latin -> Cyrillic/Greek confusable substitution). |
| `cyberjection/mutators/typoglycemia.py` | `TypoglycemiaMutator`: scrambles interior letters of words > 3 characters, first/last letters fixed. |
| `cyberjection/mutators/rot13.py` | `CaesarCipherMutator` (general shift cipher) and `ROT13Mutator` (shift 13, its own inverse). |
| `cyberjection/attacks/base.py` | `BaseStrategy` abstract interface, `ExecutionContext`, `SingleTurnResult`; the shared `_apply_mutations` mutation pre-hook every strategy calls before dispatch. |
| `cyberjection/attacks/prompt_injection.py` | `DirectPromptInjectionStrategy`: override-framing attacks aimed at forcing canary disclosure or unsafe tool execution. |
| `cyberjection/attacks/jailbreak.py` | `JailbreakStrategy`: persona/roleplay framing (Developer Mode, DAN-style, sandboxed VM simulation). |
| `cyberjection/attacks/system_extraction.py` | `SystemPromptExtractionStrategy`: probes engineered to leak a target's hidden system prompt or preceding context window. |

### Mutator chaining and ordering

`MutatorPipeline` applies mutators strictly in list order, each consuming
the previous mutator's output. Two of the built-in mutators use
randomization (`UnicodeZeroWidthMutator`, `HomoglyphMutator` at a partial
`substitution_rate`, and `TypoglycemiaMutator`); each takes an optional
`seed` and draws from a private `random.Random` instance rather than the
shared global `random` module, so a given seed reproduces byte-identical
output and seeding one mutator never perturbs unrelated code's random
state.

`Base64Mutator` should generally run **last** in a chain: any
character-level mutator applied after it (homoglyph, zero-width injection,
typoglycemia) mutates the Base64 alphabet itself and corrupts the encoded
payload rather than the underlying attack text.

### Attack strategy execution flow

Every `BaseStrategy` subclass follows the same four steps: frame the seed
prompt with attack-specific template text, run the framed prompt through
`_apply_mutations` (the strategy's configured `MutatorPipeline`, a no-op if
none is set), dispatch the mutated payload through `LiteLLMTarget.generate`,
and normalize the response into a `SingleTurnResult` via the shared
`_to_result` helper. Because dispatch goes through the same `LiteLLMTarget`
built in Phase 1, every strategy execution inherits that target's
token-bucket rate limiting, concurrency cap, and retry/backoff behavior
with no additional wiring.

## Phase 3: 3-Tier Cascade Evaluation Pipeline

Builds the cost-optimized safety evaluation engine that judges target
responses. Rather than sending every response to an expensive LLM judge,
three tiers of increasing cost and capability are chained, escalating only
when a cheaper tier can't resolve a confident verdict.

| Module | Responsibility |
|---|---|
| `cyberjection/evaluators/base.py` | `Verdict` enum (`PASS`/`FAIL`/`UNCERTAIN`), `EvaluationOutcome`, and the `BaseEvaluator` abstract interface every tier implements. |
| `cyberjection/evaluators/ahocorasick.py` | Pure-Python Aho-Corasick automaton: multi-pattern substring matching in one pass over the text, regardless of how many phrases are registered. |
| `cyberjection/evaluators/regex.py` | `RegexEvaluator` (Tier 1): Aho-Corasick-matched refusal phrases plus compiled regexes for secrets/canaries (AWS keys, JWTs, private key headers, DB connection strings). Curated pattern lists live in `cyberjection/evaluators/regexes/`. |
| `cyberjection/evaluators/llamaguard.py` | `LocalONNXGuardEvaluator` (Tier 2): local safety classifier. Runs a real ONNX session when `onnxruntime` and a model are available, otherwise a deterministic mock classifier so the tier -- and the cascade's escalation path -- is fully testable without a model file. |
| `cyberjection/evaluators/llmjudge.py` | `LLMJudgeEvaluator` (Tier 3): structured-JSON LLM-as-a-judge via `litellm.acompletion`, with a customizable grading rubric and retry/backoff on transient failures. |
| `cyberjection/evaluators/cascade.py` | `CascadeEvaluator`: chains Tier 1 -> Tier 2 -> Tier 3, short-circuiting on the first non-`UNCERTAIN` verdict. `tiers_invoked_for(outcome)` derives which tiers ran from the returned outcome alone. |

### Cascade escalation and cost model

Each tier returns the same `EvaluationOutcome` shape. The orchestrator
calls Tier 1 first; if it returns anything other than `UNCERTAIN` (a
matched refusal phrase or a leaked secret), that's the final verdict and
neither Tier 2 nor Tier 3 runs. Tier 2 (a local classifier, still $0.00 per
call) only escalates to Tier 3 when its confidence is below
`confidence_threshold` (default `0.90`). Tier 3, the only tier that makes
an external API call, is reached only for genuinely ambiguous responses.

`CascadeEvaluator` holds no mutable state on `self` during `evaluate()` --
which tiers ran for a given call is fully derivable from the returned
`judge_tier_used` field via `tiers_invoked_for()` -- so a single instance
is safe to share and call concurrently across many in-flight campaign
tests, the same way a `LiteLLMTarget` is shared across concurrent attack
executions.

Tier 1 costs sub-millisecond time for typical chat-turn-sized responses
(measured well under 1ms for responses up to ~2KB; cost scales linearly
with response length for longer text, since it's a single linear pass with
no catastrophic-backtracking-prone patterns). Tier 2's local classifier
adds 5-20ms with no network call. Only Tier 3 carries real per-call cost
and 500-2000ms latency, which is what the cascade's escalation policy is
designed to minimize exposure to.

### Tier 2 without a real model

`LocalONNXGuardEvaluator` is meant to wrap a quantized Llama Guard 3 ONNX
export via `onnxruntime.InferenceSession`, but shipping or requiring a
multi-hundred-megabyte model file isn't practical for every install or
test environment. If `model_path` is omitted, or `onnxruntime` isn't
installed, or the model fails to load, the evaluator falls back to a
deterministic mock classifier rather than raising -- so the cascade's
Tier 2 short-circuit and Tier 2-to-3 escalation paths are both exercisable
in any environment. Real inference (or a custom mock) can be supplied via
the `classifier_fn` constructor argument, which is called as
`classifier_fn(prompt_sent, response_text) -> (is_unsafe, confidence)`.

## Roadmap

| Phase | Scope |
|---|---|
| 1 | Core async architecture, declarative configuration, target abstraction gateway |
| 2 | Mutation engine (Base64, Homoglyph, Typoglycemia, Unicode zero-width, ROT13/Caesar) & single-turn attack generators (direct injection, jailbreak/roleplay, system prompt extraction) |
| 3 (current) | Three-tier cascade evaluation pipeline (regex -> local ONNX -> LLM judge) |
| 4 | Persistence layer, SQLAlchemy database models, campaign resumability |
| 5 | Stateful multi-turn adaptive attack engine (Crescendo, PAIR, TAP) |
| 6 | Command-line interface (Typer + Rich) |
| 7 | FastAPI REST backend & async task queue (Redis + Celery/Dramatiq) |
| 8 | React web dashboard & real-time monitoring console |
| 9 | Enterprise reporting (SARIF, HTML) & CI/CD security gates |
| 10 | Plugin architecture, security hardening, container deployment |

## Data model (Phases 4+)

Campaign state is tracked relationally once the persistence layer lands in
Phase 4:

```
campaigns (id, name, status, cost, started_at, finished_at)
    |
    +-- tests (id, campaign_id, strategy, prompt, response, score, verdict)
            |
            +-- turns (id, test_id, turn_number, prompt, response, latency_ms)
            +-- findings (id, test_id, severity, owasp_category, description)
            +-- metrics (test_id, prompt_tokens, completion_tokens, cost, judge_tier)
```

## Threat model summary

| Risk | Mitigation |
|---|---|
| Credential exposure via hardcoded API keys or logs | Environment-variable expansion keeps secrets out of YAML files; secret values are wrapped in `SecretStr` and never appear in reprs or logs. |
| Malicious payload execution via custom plugins (Phase 10) | Sandboxed plugin runtimes and strict input validation, planned for the plugin architecture phase. |
| Unbounded resource exhaustion from runaway multi-turn loops | `max_cost_cap` circuit breaker and `max_turns` bound (<= 25) enforced at the schema level. |

For air-gapped deployments, Tier 1 (regex) and Tier 2 (local ONNX)
evaluation, plus a local Ollama or vLLM target, allow fully offline
operation: skip `LLMJudgeEvaluator` (or set `confidence_threshold` low
enough on Tier 2 that Tier 3 is never reached) to keep every evaluation
on-box.
