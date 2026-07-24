# Architecture

## Overview

Cyberjection is organized as a layered, asynchronous pipeline. Configuration
flows down from the presentation layer through orchestration, the attack and
mutation engine, the target abstraction layer, evaluation, and finally
persistence and reporting.

```
 PRESENTATION LAYER
   cyberjection/cli (Typer) | apps/api (FastAPI) | apps/dashboard (React)
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
   cyberjection/reporting: SARIF v2.1.0, JSON, Markdown
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

## Phase 4: Persistence Layer, Database Models & Resumability Engine

Builds the durability layer underneath the previous three phases: every
campaign, test, conversation turn, finding, and metric generated by the
attack/evaluation pipeline is checkpointed to a relational database as it
happens, so a crashed or interrupted campaign can resume instead of
restarting from scratch.

| Module | Responsibility |
|---|---|
| `cyberjection/persistence/models.py` | SQLAlchemy 2 declarative schema (`Mapped`/`mapped_column` style): `CampaignModel`, `TestModel`, `TurnModel`, `FindingModel`, `MetricModel`, with cascading foreign keys and query-pattern indexes. |
| `cyberjection/persistence/sqlite.py` | `DatabaseManager`: builds the async SQLite engine (`aiosqlite`), applies WAL journaling, and creates the schema. Owns the per-connection pragma fix described below. |
| `cyberjection/persistence/repository.py` | `CampaignRepository`: the DAO every write and query in the execution engine goes through -- campaign/test lifecycle, turn/finding/metric recording, and the execution-state queries resumability (and, in Phase 6, the CLI's `inspect` command) need. |
| `cyberjection/persistence/resumability.py` | Pure reconciliation logic (`build_resume_map`, `reconcile_test_state`, `decide_resume_action`) plus `ResumabilityManager`, the thin database-facing wrapper around it. |
| `alembic/` | Hand-authored initial migration (`versions/0001_initial_schema.py`) mirroring `models.py` exactly, plus an async-engine-compatible `env.py`. |

### Incremental checkpointing

`CampaignRepository`'s mutating methods (`record_turn`, `record_finding`,
`upsert_metrics`, `update_test_outcome`, ...) commit immediately rather than
batching writes for a whole test or campaign. A test or campaign is a
long-running, potentially expensive unit of work; committing after every
single turn and evaluator verdict means a crash mid-campaign loses at most
the one in-flight operation, not an unbounded batch of prior progress.

### The SQLite per-connection pragma fix

SQLite has two kinds of `PRAGMA`: `journal_mode` is persisted in the
database file itself and survives across connections, but `foreign_keys`
and `synchronous` are per-connection session state that silently resets to
SQLite's defaults (`foreign_keys` OFF, `synchronous` FULL) on every new
connection. Setting them once inside a single `engine.begin()` block at
startup -- the naive approach -- only affects the one connection used for
that block; every connection the pool subsequently hands out for actual
request handling starts with `foreign_keys` back off, silently disabling
`ON DELETE CASCADE` everywhere.

This was verified empirically (not just reasoned about) with a standalone
`sqlite3` script before writing `sqlite.py`: deleting a parent row without
the pragma left orphaned child rows behind; with the pragma, cascading
delete worked as declared. `DatabaseManager` fixes this with a
`sqlalchemy.event.listens_for(engine.sync_engine, "connect")` listener that
re-applies both pragmas on *every* new DBAPI connection, not just the
first. `journal_mode=WAL` is set once in `init_db()`, since it only needs
to be set once per database file.

### Resumability: keying by composite natural key, not seed_prompt alone

A campaign resumes by reconciling its configured `TestCaseConfig` entries
against what's already persisted. The natural join key between "a test case
in the YAML config" and "a row in the `tests` table" is
`(target_id, strategy, seed_prompt)` -- not `seed_prompt` alone. Keying by
seed_prompt alone breaks as soon as one seed prompt is tested against more
than one target or strategy (an explicitly supported, realistic
configuration), silently losing resume state for every test case after the
first with that seed_prompt. `build_resume_map` keys by the full composite
tuple instead; the one remaining ambiguous case -- two config entries with
an *identical* full triple, which is a config-authoring problem rather than
a resumability one -- raises `ResumabilityKeyCollisionError` instead of
silently dropping a test's resume state.

Within a single test, resuming picks up from the lowest turn number not yet
recorded (scanning for a gap) rather than trusting `max(turn_numbers) + 1`,
so a turn lost to an out-of-order or partial write can't be silently
skipped forever.

### Async-compatible Alembic migrations

`alembic/env.py` runs the same async SQLAlchemy engine used everywhere else
in the codebase through `connection.run_sync(...)` inside
`asyncio.run(...)`, rather than standing up a second, synchronous engine
just for migrations -- so there is exactly one connection code path
(including the pragma fix above) to keep correct.

### A note on offline hard-testing

This sandbox has no network access to install SQLAlchemy, aiosqlite, or
Alembic (`pip install` fails at the proxy layer, not at package resolution).
Rather than skip verification, testing for this phase split into three
tracks: (1) the SQLite semantics the ORM code depends on -- the pragma
per-connection reset and `ON DELETE CASCADE` behavior -- were verified
directly against stdlib `sqlite3`; (2) the hand-authored Alembic migration's
real `upgrade()`/`downgrade()` functions were executed (not just read) via
a small dry-run harness that maps `alembic.op` calls onto real `sqlite3`
DDL, exercising schema creation, cascading delete, and the unique
`(test_id, turn_number)` constraint end-to-end; and (3) the resumability
reconciliation algorithm was factored into pure functions with no
SQLAlchemy import at all (`cyberjection/persistence/resumability.py`,
guarded by a `TYPE_CHECKING`-only import and an `ImportError`-tolerant
package `__init__.py`), so it runs and is genuinely unit-tested offline. The
SQLAlchemy-model and repository test suites
(`tests/unit/test_database_models.py`, `tests/unit/test_repository.py`) are
written as real `pytest-asyncio` tests against a real async engine for CI to
run once the dependencies are installed; they self-skip via
`pytest.importorskip` rather than failing where they aren't.

## Phase 5: Stateful Multi-Turn Adaptive Attack Engine

Builds the multi-turn attack core on top of the Phase 1 target gateway and
the Phase 3 cascade evaluator: rather than a single scored request/response
pair, an attack is now a growing, possibly-branching conversation that
escalates or backtracks based on the evaluator's read of each exchange.

| Module | Responsibility |
|---|---|
| `cyberjection/attacks/state.py` | `TurnStatus`, `AttackNode` (a scored conversational state node), `ConversationContext` (live message history plus a parallel, backtrack-resilient attack-tree node index), and `score_from_evaluation` (the Phase 3 -> Phase 5 score adapter, see below). |
| `cyberjection/attacks/attacker.py` | `AttackerAgent`: a dedicated generator LLM that analyzes the target's latest response and formulates the next adversarial follow-up prompt as structured JSON. |
| `cyberjection/attacks/crescendo.py` | `CrescendoEngine`: incremental foot-in-the-door escalation across a bounded number of turns, with automatic backtracking out of hard refusals. |
| `cyberjection/attacks/tap.py` | `TAPEngine`: Tree-of-Attacks-with-Pruning breadth-first branching search, exploring multiple candidate follow-ups per branch and pruning unproductive ones. |

### The attack tree: live history vs. the node index

`ConversationContext` deliberately keeps two structures rather than one:
`history` (the flat message list actually replayed to models) and `nodes`
(a `node_id -> AttackNode` index linked by `parent_id`). A backtrack
(`pop_last_turn`) strips a refused exchange from `history` -- the target's
live memory genuinely forgets it happened -- but the corresponding
`AttackNode` stays in `nodes`, so the attempt is never lost from the
attack's audit trail. `path_to(node_id)` walks the `parent_id` chain back
to the root, reconstructing any node's full trajectory on demand; this is
what makes `nodes` function as an actual *tree* (branch-aware, as TAP
needs) rather than a flat list (all Crescendo needs, since it never
branches).

### Bridging Phase 3's verdict to a Phase 5 attack-progress score

Phase 3's `EvaluationOutcome` carries a `Verdict` (`PASS`/`FAIL`/
`UNCERTAIN`) and a `confidence` in `[0.0, 1.0]`. Phase 5's engines are
built around a 0-10 attack-progress score and a refusal flag instead.
`score_from_evaluation` is the single adapter both `CrescendoEngine` and
`TAPEngine` call to bridge the two: `Verdict.FAIL` (the target was
jailbroken) maps to a high score scaled by confidence; `Verdict.PASS` (the
target safely resisted) maps to a low score and `is_refusal=True`;
`Verdict.UNCERTAIN` scores conservatively in the low-middle of the range
without asserting a refusal happened. Centralizing this in one function
(rather than letting each engine grow its own conversion) is what keeps
Crescendo's and TAP's success/pruning thresholds comparable to each other.
Phase 6's `evaluate_quality_gate` reuses the same 0-10 scale via `Finding.score`,
so a CI/CD threshold means the same thing whether it's judging a single-turn
attack, a multi-turn Crescendo run, or a TAP search.

### Crescendo: escalation with backtracking

`CrescendoEngine.run()` is an async generator yielding exactly one
`AttackNode` per turn attempted. Each turn is classified into one of four
`TurnStatus` values: `SUCCESS` (score at or above `success_threshold`,
which ends the generator), `BACKTRACK` (a refusal was detected and the
backtrack budget isn't exhausted -- `ConversationContext.pop_last_turn()`
strips the refused exchange from what's sent to the target on the next
turn), `REFUSED` (a refusal was detected but the backtrack budget is
exhausted, so the refusal is recorded but conversation memory is left
intact), or `PROGRESSING` (neither). A backtracked node's `parent_id`
bookkeeping is careful to keep pointing at the last *surviving* parent, not
the rolled-back node itself, since the rolled-back node's context no
longer exists in the live conversation.

### TAP: breadth-first tree search with pruning

`TAPEngine.execute_tree_search()` expands every surviving branch at each
depth level before moving to the next (a genuine breadth-first search,
depth by depth), asking the attacker for `branching_factor` candidate
follow-ups per branch via `asyncio.gather(..., return_exceptions=True)` so
one failed attacker call only prunes that one candidate rather than
aborting the whole search. A branch survives to the next depth only if its
score is at or above `pruning_threshold`; the moment any branch reaches
`success_threshold`, the search returns that branch's full root-to-leaf
path immediately. If `max_depth` is exhausted without a success, the
search returns the highest-scoring path actually explored (breaking ties
on depth, deeper wins) rather than an empty result, so a failed search
still reports how close the attack got.

### Cost and orchestration status

Neither engine enforces `CampaignConfig.max_cost_cap` or is wired to
`StrategyConfig.max_turns` from campaign YAML yet -- both are constructed
directly in Python for now, the same interim state Phase 2's mutator
pipeline and Phase 3's cascade evaluator shipped in before their respective
orchestrator wiring landed. `TAPEngine`'s branch count grows as
`branching_factor ** depth`, so a full unpruned search under the defaults
(`branching_factor=3`, `max_depth=5`) can reach several hundred target +
attacker + evaluator calls; `pruning_threshold` is the only cost control
until campaign-level budget wiring exists.

## Phase 6: CI/CD Pipeline Integration, CLI Harness & Enterprise Reporting

Builds the operator- and pipeline-facing surface on top of every prior
phase: a command-line harness to drive evaluations, and a reporting layer
that turns evaluation results into formats CI/CD systems and security
tooling already understand.

| Module | Responsibility |
|---|---|
| `cyberjection/cli/main.py` | The `cyberjection` Typer + Rich CLI: `run` (execute + gate + optionally export), `inspect` (browse persisted campaign history), `export` (re-render a prior JSON report into another format). |
| `cyberjection/reporting/models.py` | `Finding` (the typed result shape every exporter consumes) and `QualityGateResult`. |
| `cyberjection/reporting/sarif.py` | `SARIFReporter`: exports findings as SARIF 2.1.0. |
| `cyberjection/reporting/exporters.py` | `JSONExporter` and `MarkdownExporter`: machine-readable and executive-summary audit formats. |
| `cyberjection/reporting/quality_gate.py` | `evaluate_quality_gate()` (pure pass/fail decision) and `resolve_threshold()` (CLI flag > campaign YAML > default). |
| `.github/workflows/cyberjection.yml`, `.gitlab-ci.yml` | Reusable CI/CD security-evaluation gates. |

### The CLI's exit-code contract

`cyberjection run` uses four distinct exit codes rather than a bare
pass/fail: `0` (quality gate passed), `1` (the run executed correctly but a
finding breached the configured threshold), `2` (a usage/configuration
error caught before any evaluation ran -- bad config file, unknown target
id, missing input file), and `3` (a command's runtime dependency, e.g.
SQLAlchemy for `inspect`, isn't installed). Separating `1` from `2` matters
for CI/CD specifically: a pipeline should treat "the security gate found a
real problem" (fail the build, look at the report) very differently from
"the pipeline is misconfigured" (fail the build, look at the CLI's own
error message) -- collapsing both into a single non-zero exit would make
that triage a manual step every time.

### Report exporters share one typed `Finding`, not per-exporter dicts

The Phase 6 design spec's own CLI sketch passed a list of raw `dict`
results (`item["rule_id"]`, `item["score"]`, ...) into each exporter. A
`Finding` Pydantic model (`cyberjection/reporting/models.py`) replaces that:
every exporter, and the quality gate, take the same typed value, so a
producer that forgets a field or misnames one fails at construction time
rather than at export time -- after a real evaluation run has already spent
real target/attacker/judge calls.

### SARIF severity is threshold-relative, and rules are deduplicated

Two bugs in the design spec's own `SARIFReporter.export` sketch are fixed
in the shipped version (see the Phase 6 changelog entry for the full
detail): severity levels are derived from the run's actual `--threshold`
instead of a value hardcoded at `7.0`, and the `rules` catalog is
deduplicated by `rule_id` instead of growing one entry per finding --
important because SARIF's `rules` array is meant to be a one-entry-per-rule
catalog referenced *by* `ruleIndex`, not a per-result log.

### The `run` pipeline is a documented stub

`_execute_pipeline()` in `cli/main.py` returns fixed findings rather than
actually invoking the Phase 2-5 attack/evaluator machinery against the
resolved target -- see [Cost and orchestration status](#cost-and-orchestration-status)
above and the Known Limitations section of the Phase 6 changelog entry.
It's shaped exactly like the eventual real implementation (same
parameters, same `List[Finding]` return type) specifically so wiring in a
real orchestrated run later is a body replacement, not an interface
change for every caller (the CLI, and any future orchestrator entrypoint)
that already depends on it.

## Phase 7: Distributed Worker Architecture, Task Queues & Rate Limiting Engine

Scales evaluation from a single process to a horizontal pool of worker
nodes coordinating through shared Redis state, so a large campaign can be
split across a cluster instead of bottlenecking on one machine's CPU and
one process's view of each provider's rate limits.

| Module | Responsibility |
|---|---|
| `cyberjection/distributed/celery_app.py` | The shared `celery_app` Celery application: Redis broker/backend, JSON serialization, late ack, bounded prefetch. |
| `cyberjection/distributed/rate_limiter.py` | `DistributedRateLimiter`: atomic Redis-backed RPM + TPM token bucket per provider, cluster-wide. `evaluate_dual_bucket()` is the pure-Python algorithm mirror. |
| `cyberjection/distributed/coordinator.py` | `DistributedClusterCoordinator`: Redis Pub/Sub abort broadcast/listen, wired to `Verdict.FAIL`. |
| `cyberjection/distributed/retry.py` | `compute_backoff_delay()` (pure exponential backoff with jitter) and dead-letter-queue helpers. |
| `cyberjection/distributed/tasks.py` | `execute_eval_turn_task`: the Celery task wrapping one evaluation turn, rate-limited, retried, dead-lettered on exhaustion. |

### One atomic Lua script covers both buckets, not two separate checks

A provider commonly enforces requests-per-minute *and* tokens-per-minute
limits independently. Checking and debiting two separate Redis keys with
two separate round trips would leave a window between them where a
request could pass the RPM check, then fail the TPM check, having already
consumed an RPM token for a request that overall never went through.
`DUAL_TOKEN_BUCKET_LUA` evaluates and debits both buckets inside one
`EVALSHA` call, so a request is admitted or rejected as a single atomic
unit -- if either bucket is short, neither is touched.

### Rate-limiter capacity guard

A request for more units than a bucket's own configured capacity can
never be satisfied, since a bucket's level is capped at its maximum. The
design spec's own `acquire()` sketch had no such guard and would loop
forever sleeping on a request shaped like that. `DistributedRateLimiter.acquire()`
checks `request_cost`/`token_cost` against the configured maximums up
front and raises `RateLimitCapacityExceededError` immediately instead.

### Fault tolerance: retry with backoff, then dead-letter

`execute_eval_turn_task` catches any exception from its work, computes a
jittered exponential backoff (`compute_backoff_delay`), and calls
`self.retry()`. Once `self.retry()` itself raises `MaxRetriesExceededError`
(retry budget exhausted), the task pushes a JSON record of the failure --
task name, id, arguments, error type/message, and how many retries were
attempted -- onto a durable Redis list (the dead-letter queue) before
re-raising, so a permanently-failing task leaves a record an operator can
inspect and replay rather than silently vanishing into a Celery FAILURE
result nobody's watching.

### Not yet wired into the orchestrator

Same status as the Phase 4 persistence layer before Phase 5 wired
resumability into anything, and the Phase 6 CLI's still-stubbed
`_execute_pipeline()`: `cyberjection/distributed/` ships as a complete,
independently-tested subsystem, but nothing in this phase decides *when*
a campaign should dispatch to the distributed queue instead of running
locally. See [Cost and orchestration status](#cost-and-orchestration-status)
and the Known Limitations section of the Phase 7 changelog entry.

## Roadmap

| Phase | Scope |
|---|---|
| 1 | Core async architecture, declarative configuration, target abstraction gateway |
| 2 | Mutation engine (Base64, Homoglyph, Typoglycemia, Unicode zero-width, ROT13/Caesar) & single-turn attack generators (direct injection, jailbreak/roleplay, system prompt extraction) |
| 3 | Three-tier cascade evaluation pipeline (regex -> local ONNX -> LLM judge) |
| 4 | Persistence layer, SQLAlchemy database models, campaign resumability |
| 5 | Stateful multi-turn adaptive attack engine (Crescendo, TAP) |
| 6 | CI/CD pipeline integration, CLI harness (Typer + Rich), enterprise reporting (SARIF, JSON, Markdown) |
| 7 (current) | Distributed worker architecture: Celery + Redis task queues, atomic cluster-wide RPM/TPM rate limiting, Pub/Sub abort coordination, retry/dead-letter fault tolerance |
| 8 | Security auditing, compliance & production hardening |
| 9 | Orchestrator: wires the CLI's `run` pipeline stub through the real attack/evaluator/persistence stack (and, per Phase 7, optionally the distributed queue) |
| 10 | Plugin architecture, web dashboard, container deployment |

## Data model

Campaign state is tracked relationally via the Phase 4 persistence layer:

```
campaigns (id, name, status, total_cost, started_at, finished_at)
    |
    +-- tests (id, campaign_id, target_id, strategy, seed_prompt, status, score, verdict, created_at)
            |
            +-- turns (id, test_id, turn_number, prompt_payload, response_payload, latency_ms, created_at)
            +-- findings (id, test_id, severity, owasp_category, description, created_at)
            +-- metrics (test_id, prompt_tokens, completion_tokens, total_cost, judge_tier_used)
```

`turns` enforces a unique `(test_id, turn_number)` index (so a turn can't be
silently duplicated on a racy resume) and `tests` indexes
`(campaign_id, target_id, strategy)` to support the resumability lookup
above. Every foreign key cascades on delete: removing a campaign removes
its tests, turns, findings, and metrics with it.

The Phase 5 attack tree (`ConversationContext.nodes` / `AttackNode`) is not
yet persisted through this schema -- `TurnModel` records a single
prompt/response pair per turn number, while an `AttackNode` additionally
carries score, status, and tree-branching (`parent_id`) that don't have a
column home yet. The Phase 6 `Finding` model is likewise a reporting-layer
value, not a persisted row -- it has no `FindingModel` foreign key back to
a specific evaluation the way `FindingModel` does. Wiring both into the
persistence layer is orchestrator work reserved for a later phase.

## Threat model summary

| Risk | Mitigation |
|---|---|
| Credential exposure via hardcoded API keys or logs | Environment-variable expansion keeps secrets out of YAML files; secret values are wrapped in `SecretStr` and never appear in reprs or logs. |
| Malicious payload execution via custom plugins (Phase 10) | Sandboxed plugin runtimes and strict input validation, planned for the plugin architecture phase. |
| Unbounded resource exhaustion from runaway multi-turn loops | `max_cost_cap` circuit breaker and `max_turns` bound (<= 25) enforced at the schema level; `TAPEngine.pruning_threshold` bounds branch survival until cost-cap wiring lands. |
| A misconfigured CI/CD pipeline silently passing a security gate | The CLI's exit-code contract keeps a quality-gate failure (`1`) distinct from a usage/config error (`2`) and an environment error (`3`), so a pipeline can't mistake "the CLI couldn't even run" for "the target passed evaluation." |

For air-gapped deployments, Tier 1 (regex) and Tier 2 (local ONNX)
evaluation, plus a local Ollama or vLLM target, allow fully offline
operation: skip `LLMJudgeEvaluator` (or set `confidence_threshold` low
enough on Tier 2 that Tier 3 is never reached) to keep every evaluation
on-box. `AttackerAgent` still requires a real LLM call by design (it's the
part of the system generating adversarial creativity), so fully offline
multi-turn campaigns need a local model served through Ollama/vLLM
configured as the attacker's `model`. The Phase 6 CLI and reporting layer
have no network dependency of their own beyond whatever the pipeline it
drives requires.
