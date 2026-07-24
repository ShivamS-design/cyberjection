# Changelog

All notable changes to this project are documented in this file.

## [0.7.0] - Phase 7: Distributed Worker Architecture, Task Queues & Rate Limiting Engine

### Added

- `cyberjection/distributed/celery_app.py`: the shared `celery_app` Celery
  application, configured with a Redis broker/result backend, JSON
  serialization, late task acknowledgement, and a bounded worker prefetch
  multiplier so a long-running, rate-limited task can't starve other
  workers by hoarding a deep local queue.
- `cyberjection/distributed/rate_limiter.py`: `DistributedRateLimiter`, an
  atomic Redis-backed rate limiter enforcing both requests-per-minute
  (RPM) *and* tokens-per-minute (TPM) per target provider, cluster-wide.
  Both buckets are checked and debited in a single atomic Lua script
  (`DUAL_TOKEN_BUCKET_LUA`) so a request is never partially admitted.
  `evaluate_dual_bucket()` is a pure-Python function documented as a
  line-for-line mirror of that script, kept separately hard-testable.
- `cyberjection/distributed/coordinator.py`: `DistributedClusterCoordinator`,
  broadcasting and listening for cluster-wide abort signals over Redis
  Pub/Sub. `broadcast_if_failing()` wires the coordinator directly to
  `cyberjection.evaluators.base.Verdict`, broadcasting only on `Verdict.FAIL`.
- `cyberjection/distributed/retry.py`: `compute_backoff_delay()` (pure
  exponential backoff with jitter, `T_wait = base * 2^retry + jitter`) and
  `push_to_dead_letter_queue()` / `build_dead_letter_payload()` for routing
  permanently-failed tasks to a durable Redis list.
- `cyberjection/distributed/tasks.py`: `execute_eval_turn_task`, the Celery
  task wrapping a single evaluation turn -- acquires a rate-limit token
  before doing any work, retries transient failures with exponential
  backoff, and routes exhausted-retry failures to the dead-letter queue.
- Unit test suite: `test_rate_limiter.py`, `test_retry.py`,
  `test_coordinator.py`, `test_distributed_tasks.py` -- including a
  50-way concurrent `acquire()` race against a 10-unit bucket asserting
  exactly 10 succeed, the atomicity claim exercised directly rather than
  assumed.
- `redis>=5.0` and `celery>=5.4` added to `pyproject.toml` dependencies.

### Fixed

- The Phase 7 design spec's own `DistributedRateLimiter` sketch accepted a
  `max_tpm` constructor argument but never used it anywhere in the class
  body -- `acquire()` only ever checked the RPM bucket, so a caller could
  exceed a provider's tokens-per-minute cap without the limiter ever
  noticing, despite Task 7.2's own description promising both. Implemented
  a real second (TPM) bucket, checked and debited atomically alongside RPM
  in one Lua script call so neither bucket is ever partially consumed.
- The spec's `acquire()` sketch loops `while True: ... await asyncio.sleep(...)`
  with no check that the requested amount can ever fit in the bucket. A
  request for more units than the bucket's own capacity (e.g. a
  misconfigured per-call token estimate exceeding the provider's
  `max_tpm`) can never succeed no matter how long the caller waits, since
  a bucket's level is capped at its max -- that sketch would block
  forever. Added an immediate `RateLimitCapacityExceededError` guard for
  exactly this case.
- Task 7.1 explicitly directs creating a separate `celery_app.py` for "the
  central Celery application," but the spec's own Artifact 2 code sketch
  defines `celery_app = Celery(...)` inline inside `tasks.py` instead --
  workable for a single task module, but not once a second module or the
  `celery -A ... worker` CLI invocation needs the same app instance.
  Resolved in favor of Task 7.1's explicit file layout: `celery_app.py`
  owns the app and its configuration; `tasks.py` imports the shared
  instance.
- The spec's `execute_eval_turn_task` sketch constructed a brand new
  `DistributedRateLimiter` (and therefore a new Redis connection, plus a
  redundant `SCRIPT LOAD` re-upload) on every single task invocation.
  Worker processes are long-lived, so the limiter is now cached per
  `(redis_url, provider_id, max_rpm, max_tpm)` and reused across every
  task a given worker process executes.
- The spec's `coordinator.py` sketch's `listen_for_aborts` broke out of
  the Pub/Sub listen loop on the first abort message without
  unsubscribing or closing the pubsub connection, leaking a subscription
  per listener. Wrapped in `try`/`finally` so the connection is always
  cleaned up, including when the loop exits without ever seeing a message.
- The spec's Definition of Done claims "Fault Recovery Tested: ...
  failing items to the dead-letter queue," but neither the spec's task
  breakdown (Task 7.5) nor its own code artifacts actually implement any
  dead-letter handling -- `execute_eval_turn_task`'s sketch calls
  `self.retry()` and stops there. Implemented the missing piece:
  `retry.py`'s `push_to_dead_letter_queue()`, invoked from `tasks.py` when
  `self.retry()` itself raises `MaxRetriesExceededError`.
- The spec's own verification commands (`poetry run pytest ...`,
  `poetry run celery ...`) assume Poetry, which this project has never
  used -- `pyproject.toml` has used a `hatchling` build backend with a
  plain `pip install -e ".[dev]"` flow since Phase 1 (also corrected in
  Phase 6's CI workflow). Documented the equivalent `pip`-based commands
  instead.

### Known limitations

- `cyberjection/distributed/` is not wired into the single-node
  orchestrator from earlier phases -- there is no code path yet that
  decides whether a campaign runs locally or dispatches to the
  distributed queue. This mirrors how the Phase 4 persistence layer
  landed standalone before Phase 5 wired resumability into anything;
  that integration is left for a later phase.
- `DistributedRateLimiter.acquire()`'s `token_cost` parameter is a
  caller-supplied *pre-flight estimate* of prompt+completion tokens, not
  a value reconciled against the real usage a provider reports after a
  call completes -- exact per-call token cost usually isn't known until
  the response arrives. Reconciling the estimate against real usage is a
  coordination concern for whichever later phase wires this limiter into
  `cyberjection.providers.litellm_provider.LiteLLMTarget`.
- The dead-letter queue is a single Redis list shared by every
  provider/target on a given Redis instance rather than partitioned per
  target -- intentional (one place to look for every cluster-wide
  failure), but means a very high-failure-rate provider can dominate the
  queue's contents.
- `execute_eval_turn_task`'s body is a scaffolded evaluation-turn
  placeholder (acquires a rate-limit token, then a no-op await stands in
  for the real provider call), consistent with the Phase 7 spec's own
  "mock API execution bridge" scope -- there is no live campaign/target
  context available from a bare Celery task signature to make a real
  provider call with yet.

### Offline test harness changes

Hard-testing this phase's core claims -- atomic Redis-backed rate
limiting and Celery task retry/dead-letter behavior -- required more than
the usual offline shims, since neither `redis`, `celery`, a Redis server,
nor a Lua interpreter is available in this sandbox (confirmed: `pip
install redis` fails with the same proxy-403 error every previous
phase's dependency installs have hit).

- Added a functional in-memory `redis.asyncio` double
  (`/tmp/_shims/redis/asyncio.py`, environment-local, not part of the
  shipped package) implementing hash, list, and Pub/Sub commands plus
  `SCRIPT LOAD`/`EVALSHA`. Because no Lua interpreter is available to
  execute `DUAL_TOKEN_BUCKET_LUA` itself, `EVALSHA` recognizes that
  specific script (by a marker comment in its source) and dispatches to
  `evaluate_dual_bucket()` -- the documented pure-Python mirror of the
  same algorithm -- executed under an `asyncio.Lock`, reproducing Redis's
  single-threaded atomicity guarantee closely enough that a genuine
  50-way concurrency race test against it either passes or fails
  meaningfully, rather than trivially passing because nothing was
  actually contending.
- Added a functional `celery` double (`/tmp/_shims/celery/`) that runs
  tasks eagerly in-process (there's no broker to dispatch to), but
  otherwise exercises the real `Task.retry()` / `MaxRetriesExceededError`
  control flow: a bound task's `self.retry()` raises `Retry` while budget
  remains and `MaxRetriesExceededError` once exhausted, exactly as real
  Celery's own `Task.retry()` does, so `tasks.py`'s own try/except around
  `self.retry()` for dead-letter routing is exercised for real rather
  than mocked away.
- This is a heavier-weight version of the strategy Phase 6 used for
  `typer`/`rich` (build a genuine shim on top of whatever *is* available)
  rather than Phase 4's for SQLAlchemy (declare the dependency, self-skip
  the tests offline via `pytest.importorskip`) -- chosen because Phase
  7's core deliverables are specifically about concurrency/atomicity
  behavior that a self-skipped test suite would never actually exercise.
  In a real deployment with `redis`/`celery` installed and a reachable
  Redis server (per the Definition of Done's own `docker run
  redis:alpine` prerequisite), the same test files run unmodified against
  the genuine packages -- nothing in `tests/unit/test_rate_limiter.py`,
  `test_coordinator.py`, or `test_distributed_tasks.py` depends on shim
  internals, only on the documented `redis.asyncio`/`celery` surface.

## [0.6.0] - Phase 6: CI/CD Pipeline Integration, CLI Harness & Enterprise Reporting

### Added

- `cyberjection/cli/main.py`: the `cyberjection` Typer + Rich CLI with
  three commands. `run` loads a campaign config, resolves `--target`,
  executes the (currently stubbed) evaluation pipeline, applies the
  quality gate, renders a Rich summary table, and optionally writes
  SARIF/JSON/Markdown reports. `inspect` browses persisted campaign
  history via `CampaignRepository.list_recent_campaigns`. `export`
  re-renders a prior `run --json-out` report into SARIF or Markdown
  without re-running an evaluation.
- `cyberjection/reporting/models.py`: `Finding` (the typed shape every
  Phase 6 exporter consumes, replacing the design spec's raw
  `dict["rule_id"]`-style results) and `QualityGateResult`.
- `cyberjection/reporting/sarif.py`: `SARIFReporter`, exporting findings as
  SARIF 2.1.0 for GitHub Advanced Security / GitLab Security Dashboard
  ingestion.
- `cyberjection/reporting/exporters.py`: `JSONExporter` (machine-readable
  audit log with a summary block) and `MarkdownExporter` (executive
  pass/fail summary with a per-finding table).
- `cyberjection/reporting/quality_gate.py`: `evaluate_quality_gate()` (a
  pure pass/fail decision -- a finding scoring at or above the threshold
  fails the gate) and `resolve_threshold()` (CLI flag > campaign YAML >
  hardcoded default `7.0`, with `0.0` treated as a legitimate explicit
  threshold rather than "not given").
- `QualityGateConfig` (`cyberjection/config/schema.py`): an optional
  `quality_gate.threshold` section on `CampaignConfig`, so a threshold can
  travel with a campaign's version-controlled YAML.
- `CampaignRepository.list_recent_campaigns()`
  (`cyberjection/persistence/repository.py`): newest-first campaign
  listing, the `inspect` command's data source -- nothing before Phase 6
  needed to enumerate campaigns rather than look one up by known id.
- `UnknownTargetError` (`cyberjection/utils/exceptions.py`): raised when
  `--target` references an id absent from the loaded campaign config.
- `.github/workflows/cyberjection.yml` and `.gitlab-ci.yml`: reusable
  pull-request security gates running `cyberjection run` and uploading the
  SARIF report as a build artifact / GitHub code-scanning upload.
- Unit test suite: `test_cli.py`, `test_sarif_exporter.py`,
  `test_exporters.py`, `test_quality_gate.py`, plus new cases in
  `test_repository.py` for `list_recent_campaigns`.

### Fixed

- The Phase 6 design spec's own `SARIFReporter.export` sketch hardcoded
  the error/warning severity split at a fixed score of `7.0`, independent
  of whatever `--threshold` the run actually used -- a finding scoring 5.0
  under a `--threshold 4.0` run had already failed that run's gate but
  would still be reported as `note`/`warning` in the SARIF output. Fixed
  by threading the effective threshold through `export()` so SARIF
  severity always agrees with the quality-gate decision for the same run.
- The spec's `SARIFReporter.export` sketch appended one `rules` catalog
  entry per finding with no deduplication, so a rule id that fired on more
  than one test case would appear multiple times in `tool.driver.rules`
  under different `ruleIndex` values -- SARIF's `rules` array is meant to
  be a one-entry-per-rule-id catalog referenced *by* `ruleIndex`, not a
  per-result log. Fixed by keying the catalog on `rule_id`, deduplicated;
  every result referencing a repeated rule id now points at that rule's
  single catalog entry.
- The spec's Task 6.5 asks for thresholds in a flat top-level
  `cyberjection/config.py` module, which does not exist in this codebase
  -- configuration has been the `cyberjection.config` *package*
  (`schema.py` + `loader.py`) since Phase 1. Threaded the threshold
  through as `QualityGateConfig` on `CampaignConfig` instead, consistent
  with how `RateLimitConfig`/`StrategyConfig` already work.
- The spec's GitHub Actions workflow sketch installs dependencies via
  `pip install poetry && poetry install`. This project has never used
  Poetry -- `pyproject.toml` has declared a `hatchling` build backend with
  a plain `pip install -e ".[dev]"` flow since Phase 1, and no
  `poetry.lock` exists anywhere in the repo. The shipped workflow (and its
  new GitLab CI counterpart) installs and invokes the project the same way
  every other phase's documented Quickstart does.
- `pyproject.toml`'s `[project.scripts]` entry has pointed
  `cyberjection = "apps.cli.main:app"` at a module that has never existed
  in this repository (no `apps/` directory) since it was first declared in
  Phase 1, anticipating a CLI that hadn't been built yet. Fixed to point at
  the real `cyberjection.cli.main:app` built this phase.

### Known limitations

- `_execute_pipeline()` (`cyberjection/cli/main.py`) is an explicit stub
  returning fixed findings rather than actually invoking the Phase 2-5
  attack/evaluator machinery (mutators, single-turn strategies, the
  cascade evaluator, Crescendo/TAP) against the resolved target. Wiring a
  real orchestrated run is out of scope for every phase shipped so
  far -- Phase 4's and Phase 5's changelogs both note that no
  orchestrator loop exists yet -- and this stub is shaped exactly like the
  eventual real implementation (same signature, same return type) so a
  later phase only needs to replace its body.
- `inspect` depends on the Phase 4 persistence layer (SQLAlchemy +
  aiosqlite); when those aren't installed it reports a clear environment
  error (exit code 3) rather than a traceback, but there is nothing to
  browse until they are.
- SARIF export validates structurally against a locally-authored minimal
  SARIF 2.1.0 schema subset (see `test_sarif_exporter.py`), not the full
  official ~300KB `sarif-schema-2.1.0.json` -- this sandbox has no network
  access to fetch it for validation.

### Offline test harness changes

Extending and hard-testing this phase surfaced three real, previously
latent bugs in the offline verification tooling itself (not shipped as
part of the deliverable):

- The offline `typer` shim (built directly on the real `click` library,
  since this sandbox has no network access to install `typer`/`rich`)
  originally passed an explicit `default=None` to every `click.Option`,
  including required ones. Click 8.4's `Sentinel.UNSET` model only enforces
  a missing required option when its default is still the sentinel --
  an explicit `default=None` satisfies `consume_value()` before the
  required check ever runs, silently defeating `required=True` for every
  Optional-typed required CLI option (`--target` could be omitted with no
  error). Caught by a test asserting a `--target`-less invocation exits 2;
  fixed by omitting the `default` kwarg entirely for required options.
- The offline `rich.console.Console` shim resolved `sys.stdout` once at
  object-construction time (module import time) rather than dynamically on
  each `print()` call. `click.testing.CliRunner` captures output by
  reassigning the `sys.stdout` module attribute for the duration of an
  invocation, not by mutating the stream in place, so a `Console` built
  before any `CliRunner.invoke()` call held a stale reference and every
  `console.print()` silently bypassed test capture, writing straight to
  the real terminal instead. Caught when CLI tests asserting on
  `result.output` failed despite correct exit codes and correctly printed
  (real, terminal-visible) text. Fixed by resolving `sys.stdout` lazily via
  a `file` property, matching real `rich.console.Console`'s own behavior.
- The offline `pydantic` shim's `BaseModel` had no `__eq__`, so two
  separately constructed model instances with identical field values
  compared unequal by object identity -- caught by a `Finding` JSON
  round-trip test. Fixed by adding value-based equality (type + `model_dump()`
  comparison), matching real pydantic v2.
- `run_tests.py` (the offline test collector/runner) only scanned
  `tests/conftest.py` for `@pytest.fixture`-decorated functions, not
  fixtures declared directly in a test module. Every earlier phase's
  module-level fixture usage happened to live in files this sandbox skips
  entirely (missing `sqlalchemy`), so the gap went undetected until
  `test_cli.py`, the first offline-runnable file to declare one. Fixed by
  scanning each test module for its own fixtures in addition to
  conftest.py's, with module-level fixtures taking precedence on a name
  collision (matching real pytest's closer-scope-wins resolution).

## [0.5.0] - Phase 5: Stateful Multi-Turn Adaptive Attack Engine

### Added

- `cyberjection/attacks/state.py`: `TurnStatus` (`PROGRESSING`/`REFUSED`/
  `SUCCESS`/`BACKTRACK`), `AttackNode` (a single conversational state node,
  0-10 attack-progress `score`, `parent_id`-linked), and
  `ConversationContext` -- live conversation memory (`history`) plus a
  parallel attack-tree node index (`nodes`) that survives backtracking even
  after `history` forgets a rolled-back turn. `path_to()` reconstructs any
  node's full root-to-leaf trajectory from `parent_id` links; `best_score()`
  reports the highest attack-progress score reached anywhere in the tree.
- `score_from_evaluation()`: bridges Phase 3's `EvaluationOutcome`
  (`Verdict` + 0.0-1.0 confidence) onto the 0-10 attack-progress score and
  refusal flag Phase 5's engines are built around.
- `cyberjection/attacks/attacker.py`: `AttackerAgent`, generating adaptive
  multi-turn follow-up prompts via structured JSON output
  (`AttackerResponse`: `analysis`, `refusal_detected`, `next_prompt`), with
  retry/backoff on transient failures.
- `cyberjection/attacks/crescendo.py`: `CrescendoEngine`, an incremental
  foot-in-the-door multi-turn escalation strategy. `run()` is an async
  generator yielding one `AttackNode` per turn, backtracking
  (`ConversationContext.pop_last_turn`) out of turns that hit a hard
  refusal so the target's memory doesn't carry the refusal forward.
- `cyberjection/attacks/tap.py`: `TAPEngine`, a Tree-of-Attacks-with-Pruning
  breadth-first branching search. Expands every surviving branch at each
  depth level in parallel, prunes branches scoring below a threshold, and
  returns the full winning path -- or, if nothing reached the success
  threshold, the best-scoring path actually explored.
- `LiteLLMTarget.generate_conversation()`
  (`cyberjection/providers/litellm_provider.py`): sends a caller-owned,
  growing message history to a target as-is, reusing the exact same
  target-scoped rate limiting and retry/backoff as `generate()`, so
  multi-turn attack traffic is governed by the same policy as single-turn
  traffic against the same target.
- `AttackerGenerationError` (`cyberjection/utils/exceptions.py`): raised
  when the attacker agent can't produce a next payload after exhausting
  retries. Unlike the Tier 3 judge's `Verdict.UNCERTAIN` fallback, there's
  no safe placeholder next-prompt value, so a multi-turn engine aborts that
  attack trajectory instead of sending a fabricated prompt.
- Unit test suite: `test_attack_state.py`, `test_attacker_agent.py`,
  `test_crescendo_engine.py`, `test_tap_pruning.py`, plus three new cases
  in `test_litellm_provider.py` covering `generate_conversation` directly.

### Fixed

- The Phase 5 spec's own `CrescendoEngine.run()` code yielded the same
  `AttackNode` twice on any turn that triggered a backtrack (once inside
  the backtrack branch, once via an unconditional `yield` immediately
  after it). Caught with a test asserting exactly one node per turn;
  `run()` now yields exactly once per turn attempted regardless of status.
- The Phase 5 spec's `TAPEngine.execute_tree_search()` pseudocode had
  `active_branches = next_generation_branches` and the search's final
  `return` sitting one indent level too deep -- taken literally, the
  search would terminate after a single depth level regardless of
  `max_depth`, and `active_branches` would be reassigned mid-way through
  processing the current depth's branches rather than after all of them
  finished. Reimplemented as a straightforward breadth-first
  depth-by-depth expansion; verified with a test that explores 4 full
  depth levels under threshold settings that neither prune nor succeed.
- The spec's `TAPEngine` and `CrescendoEngine` code assumed
  `eval_result.score` (0-10) and `eval_result.is_refusal` (bool) directly
  on the evaluator's return value; neither field exists on Phase 3's real
  `EvaluationOutcome` (which has `verdict` and a 0.0-1.0 `confidence`
  instead). Fixed by adding `score_from_evaluation()` as the one place both
  engines convert between the two phases' score semantics, rather than
  each engine growing its own (and inevitably diverging) conversion.
- A first draft of `TAPEngine`'s "return the best partial path when no
  branch succeeds" logic picked the *first* node it encountered among
  several tied for the highest score, because `max()` keeps the first item
  on ties and `ConversationContext.nodes` iterates in insertion order. On
  a tree where every branch scored identically, this returned a
  barely-explored, shallow path instead of the branch that actually made
  it furthest. Caught by a test with 4 depth levels scoring identically;
  fixed by breaking ties on `depth` (deeper wins) in addition to `score`.
- The Phase 5 spec's own `AttackerAgent` design referenced
  `cyberjection.gateways.litellm_gateway.LiteLLMGateway`, a class that
  doesn't exist anywhere in this codebase. `AttackerAgent` instead calls
  `litellm.acompletion` directly with structured JSON output and
  retry/backoff, mirroring the exact pattern `LLMJudgeEvaluator` (Phase 3)
  already established for the same reason: attacker generation is
  orchestration tooling, not attack traffic against a target under test.

### Known limitations

- Neither `CrescendoEngine` nor `TAPEngine` is wired into an orchestrator
  loop or the Phase 4 persistence layer yet -- turns aren't automatically
  checkpointed via `CampaignRepository`. That wiring is orchestrator work
  reserved for a later phase, consistent with how Phase 4's repository and
  resumability engine were shipped as a standalone, tested API first.
- `TAPEngine`'s branch count grows as `branching_factor ** depth`; with
  the defaults (`branching_factor=3`, `max_depth=5`) a full unpruned search
  could reach several hundred target + attacker + evaluator calls. There's
  no built-in cost cap yet beyond `pruning_threshold` naturally trimming
  unproductive branches -- wiring `CampaignConfig.max_cost_cap` into these
  engines is future orchestrator work.
- `StrategyConfig.max_turns` (Phase 1 schema, capped at 25) is not yet
  automatically wired to construct a `CrescendoEngine` from campaign YAML;
  callers construct `CrescendoEngine`/`TAPEngine` directly in Python for
  now, the same interim state Phase 2's mutator pipeline and Phase 3's
  cascade evaluator were shipped in before orchestrator wiring landed.

## [0.4.0] - Phase 4: Persistence Layer, Database Models & Resumability Engine

### Added

- SQLAlchemy 2 declarative schema (`cyberjection/persistence/models.py`,
  `Mapped`/`mapped_column` style): `CampaignModel`, `TestModel`,
  `TurnModel`, `FindingModel`, `MetricModel`. Includes a unique
  `(test_id, turn_number)` index on `turns`, a composite
  `(campaign_id, target_id, strategy)` index on `tests` to support
  resumability lookups, and `ON DELETE CASCADE` on every foreign key.
- `DatabaseManager` (`cyberjection/persistence/sqlite.py`): async SQLite
  engine/session factory (`aiosqlite`), WAL journal mode, schema creation
  with automatic parent-directory creation, and an `in_memory()` classmethod
  (`StaticPool`-backed) for tests.
- `CampaignRepository` (`cyberjection/persistence/repository.py`): the DAO
  for campaign/test lifecycle, turn/finding/metric recording, and the
  execution-state queries (`list_incomplete_tests`, `get_campaign_with_tests`,
  `get_test_with_history`, ...) resumability and reporting need. Every
  mutating method commits immediately, so a checkpoint is durable the
  instant it's written rather than batched.
- Campaign resumability (`cyberjection/persistence/resumability.py`):
  `build_resume_map` / `reconcile_test_state` / `decide_resume_action`, a
  pure reconciliation algorithm with no SQLAlchemy dependency, plus
  `ResumabilityManager`, the thin database-facing wrapper around it. Resume
  state is keyed by the composite `(target_id, strategy, seed_prompt)`
  natural key, and a partially-completed test resumes from the lowest
  missing turn number rather than trusting `max(turn_numbers) + 1`.
- Alembic migrations: a hand-authored initial migration
  (`alembic/versions/0001_initial_schema.py`) mirroring `models.py`
  field-by-field, and an async-engine-compatible `alembic/env.py` that runs
  migrations through `connection.run_sync(...)` inside `asyncio.run(...)`
  rather than a second, synchronous engine.
- Unit test suite: `tests/unit/test_resumability_engine.py` (pure-function
  tests against plain stand-in objects -- turn gap detection, composite-key
  collision handling, and every `ResumeDecision` branch) plus
  `tests/unit/test_database_models.py` and `tests/unit/test_repository.py`
  (real `pytest-asyncio` tests against a real async engine, self-skipping
  via `pytest.importorskip` where SQLAlchemy isn't installed).

### Fixed

- SQLite's `PRAGMA foreign_keys` and `PRAGMA synchronous` are per-connection
  session state that resets to SQLite's defaults (`foreign_keys` OFF) on
  every new pooled connection, unlike `journal_mode`, which persists in the
  database file. Setting these once at startup inside a single
  `engine.begin()` block -- the naive approach -- silently leaves
  `ON DELETE CASCADE` disabled on every connection the pool hands out
  afterward. Verified with a standalone `sqlite3` script before writing any
  ORM code (orphaned rows without the pragma, clean cascade with it). Fixed
  with a `sqlalchemy.event.listens_for(engine.sync_engine, "connect")`
  listener in `DatabaseManager` that re-applies both pragmas on every new
  connection, not just the first.
- The originally sketched resumability lookup keyed persisted test state by
  `seed_prompt` alone, which silently collides whenever two test cases in
  the same campaign share a seed_prompt but differ in target or strategy --
  a realistic, explicitly supported configuration (e.g. one seed prompt run
  against several targets). Caught during design review, before any code
  depended on the seed_prompt-only key. Fixed by keying on the full
  `(target_id, strategy, seed_prompt)` composite instead, with an explicit
  `ResumabilityKeyCollisionError` for the one case that's still genuinely
  ambiguous (two config entries with an identical full triple).
- `SQLite doesn't create missing parent directories for a file-based
  database`: `DatabaseManager.init_db()` now creates the database file's
  parent directory before the engine's first connection, rather than
  failing on a fresh checkout with no `.cyberjection/` directory yet.

### Known limitations

- This sandbox has no network access to install SQLAlchemy, aiosqlite, or
  Alembic, so the ORM-dependent test suites
  (`test_database_models.py`, `test_repository.py`) could not be executed
  here; they're written as real tests for CI to run once the dependencies
  are installed, and self-skip cleanly rather than failing in the meantime.
  What *was* verified directly in this environment: the SQLite pragma and
  cascade-delete semantics via stdlib `sqlite3`, the hand-authored Alembic
  migration's actual `upgrade()`/`downgrade()` functions executed against a
  real (if minimally shimmed) `sqlite3` connection, and the full
  resumability reconciliation algorithm via genuine offline unit tests.
- `CampaignRepository` and `ResumabilityManager` are not yet wired into an
  orchestrator loop -- that wiring, along with the worker pool that will
  call them per-turn, is Phase 5+ scope. They're complete and tested as a
  standalone persistence API for now.
- `LocalONNXGuardEvaluator`'s judge tier and evaluation results aren't yet
  automatically persisted via `MetricModel.judge_tier_used`; callers wire
  `CascadeEvaluator` outcomes into `CampaignRepository.upsert_metrics`
  manually until the orchestrator lands.

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
