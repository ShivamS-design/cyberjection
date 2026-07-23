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

This is the current implementation. It covers the bottom two layers of the
diagram above (target abstraction) plus the configuration layer that feeds
the orchestrator in later phases.

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

## Roadmap

| Phase | Scope |
|---|---|
| 1 (current) | Core async architecture, declarative configuration, target abstraction gateway |
| 2 | Mutation engine (Base64, Homoglyph, Typoglycemia, Unicode, Pig Latin) & single-turn attack generators (direct injection, jailbreaks, roleplay, DAN) |
| 3 | Three-tier cascade evaluation pipeline (regex -> local ONNX -> LLM judge) |
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
operation once Phases 2-3 land.
