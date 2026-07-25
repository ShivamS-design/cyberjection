# Testing guide

## Running the suite

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v
mypy cyberjection/config/ cyberjection/providers/ cyberjection/mutators/ cyberjection/attacks/ cyberjection/evaluators/ cyberjection/plugins/ cyberjection/api/
pytest tests/unit/ --cov=cyberjection --cov-report=term-missing
```

To run only the Phase 2 suite:

```bash
pytest tests/unit/test_mutators.py tests/unit/test_mutator_pipeline.py tests/unit/test_single_turn_attacks.py -v
```

To run only the Phase 3 suite:

```bash
pytest tests/unit/test_regex_evaluator.py tests/unit/test_onnx_evaluator.py tests/unit/test_llm_judge.py tests/unit/test_cascade_escalation.py -v
```

To run only the Phase 4 suite:

```bash
pytest tests/unit/test_resumability_engine.py tests/unit/test_database_models.py tests/unit/test_repository.py -v
```

`test_database_models.py` and `test_repository.py` call
`pytest.importorskip("sqlalchemy")` / `pytest.importorskip("aiosqlite")` at
module scope and skip cleanly if those packages aren't installed;
`test_resumability_engine.py` has no such dependency and always runs.

To run only the Phase 5 suite:

```bash
pytest tests/unit/test_attack_state.py tests/unit/test_attacker_agent.py tests/unit/test_crescendo_engine.py tests/unit/test_tap_pruning.py -v
```

To run only the Phase 6 suite:

```bash
pytest tests/unit/test_cli.py tests/unit/test_sarif_exporter.py tests/unit/test_exporters.py tests/unit/test_quality_gate.py -v

# CLI harness smoke check
cyberjection --help
```

`test_cli.py` calls `pytest.importorskip("typer")` at module scope, the
same self-skip convention `test_database_models.py`/`test_repository.py`
use for `sqlalchemy` -- in an environment with neither `typer` nor a
compatible offline shim on `sys.path`, it skips cleanly rather than
failing collection.

To run only the Phase 7 suite:

```bash
pytest tests/unit/test_rate_limiter.py tests/unit/test_retry.py tests/unit/test_coordinator.py tests/unit/test_distributed_tasks.py -v
```

Unlike the Phase 4/6 suites above, none of these four files
`pytest.importorskip` -- `redis` and `celery` are hard dependencies (see
`pyproject.toml`), and `test_rate_limiter.py`/`test_coordinator.py`/
`test_distributed_tasks.py` exercise `DistributedRateLimiter`,
`DistributedClusterCoordinator`, and the Celery task directly through the
real `redis.asyncio`/`celery` import surface. Running them against a real
deployment requires a reachable Redis instance (`docker run -d --name
cyberjection-redis -p 6379:6379 redis:alpine`, matching the Phase 7 spec's
own prerequisite); `test_retry.py`'s pure backoff/payload-builder tests
need neither Redis nor Celery and always run.

To run only the Phase 8 suite:

```bash
pytest tests/unit/test_input_validation.py tests/unit/test_audit_log.py tests/unit/test_secrets_audit.py tests/unit/test_dependency_audit.py tests/unit/test_compliance.py -v

# hardening audit smoke check (dependency + secrets scan of the repo itself)
cyberjection audit
```

None of the five files above `pytest.importorskip` anything -- every
`cyberjection.security` module is pure stdlib plus, for
`dependency_audit.py`, an optional `subprocess` call to `pip-audit` that
degrades to an honest `source="unavailable"` result rather than skipping
or failing when the `security` extra isn't installed. `test_dependency_audit.py`
exercises that real fallback path directly rather than mocking it.

To run only the Phase 9 suite:

```bash
pytest tests/unit/test_orchestrator.py -v
```

`test_orchestrator.py` needs no `pytest.importorskip` -- persistence tests
use a duck-typed `_FakeRepository`/`_FakeResumabilityManager` rather than
a real database, and multi-turn tests replace `CrescendoEngine`/`TAPEngine`
with scripted stand-ins rather than requiring a real LLM. Single-turn
tests run through the real strategy classes and `LiteLLMTarget` with
`litellm.acompletion` monkeypatched, the same convention
`test_single_turn_attacks.py` uses, so this file also catches wiring bugs
between the orchestrator and the real attack/target stack.

To run only the Phase 10 suite:

```bash
pytest tests/unit/test_registries.py tests/unit/test_plugins.py tests/unit/test_api.py tests/unit/test_api_persistence.py -v

# CLI smoke checks
cyberjection plugins
cyberjection serve --help
```

`test_registries.py` and `test_plugins.py` need no `pytest.importorskip`
-- the three new subsystem registries (`cyberjection.attacks.registry`,
`cyberjection.evaluators.registry`, `cyberjection.reporting.registry`)
and `cyberjection.plugins.discover_plugins` are pure Python with no
third-party dependency, and `test_plugins.py` exercises entry-point
discovery against fake `_FakeEntryPoint` objects rather than a real
installed distribution. `test_api.py` (the ASGI toolkit, `/api/health`,
`/api/plugins`, and the "persistence unavailable" 503 path) also always
runs -- `cyberjection.api.asgi`/`cyberjection.api.app` have no
third-party dependency of their own (see that module's docstring for why
it isn't built on FastAPI). `test_api_persistence.py` (the campaign/test
endpoints' happy path against a real in-memory database) does
`pytest.importorskip("sqlalchemy")`/`("aiosqlite")` at module scope and
self-skips, same as `test_database_models.py`/`test_repository.py`.

**Not verified in this sandbox:** `apps/dashboard`'s TypeScript/React
source has no offline package registry access to install
`npm`/`typescript`/`vite` against in the environment this project was
hard-tested in (`npm view` returns `403 Forbidden` from the sandbox's
network allowlist, the same constraint that blocks `pip install
fastapi`), so the dashboard could not be `npm run build`/`tsc --noEmit`
verified here. Its source was written and reviewed against the exact
JSON shapes `cyberjection.api.app`'s own tests
(`test_api.py`/`test_api_persistence.py`) assert on, and kept
dependency-minimal (`react`, `react-dom`, `react-router-dom` only, no
UI framework) to reduce the surface that could be wrong. Verifying it
with a real `npm install && npm run build` in an environment with
registry access is a recommended follow-up before a production
deployment.

## Layout

| File | Covers |
|---|---|
| `tests/unit/test_config_loader.py` | Environment-variable expansion (including the single-pass, non-recursive guarantee), YAML parsing errors, missing/malformed files, and end-to-end loading of `examples/quickstart.yaml`. |
| `tests/unit/test_schema_validation.py` | Field-level constraints (ranges, required fields), duplicate-id rejection, cross-reference validation between tests and their targets/strategies, and independence of `default_factory` fields across instances. |
| `tests/unit/test_litellm_provider.py` | The provider adapter: request construction, retry/backoff behavior, exception classification, concurrency limits, cancellation handling, the token-bucket rate limiter, and `generate_conversation` (Phase 5: multi-turn message replay, no injected system prompt, same rate limiter/semaphore as `generate`). |
| `tests/unit/test_mutators.py` | Every concrete mutator's transformation logic, seeded reproducibility of the randomized mutators, and the alias registry (registration, collision handling, unknown-alias lookup). |
| `tests/unit/test_mutator_pipeline.py` | `MutatorPipeline` chaining order, empty-pipeline passthrough, and that reordering mutators changes the output. |
| `tests/unit/test_single_turn_attacks.py` | `DirectPromptInjectionStrategy`, `JailbreakStrategy`, and `SystemPromptExtractionStrategy` executed against a mocked `LiteLLMTarget`: framing, mutation-pipeline application, and `SingleTurnResult` population. |
| `tests/unit/test_regex_evaluator.py` | The Aho-Corasick automaton (a textbook overlapping-match case and a brute-force cross-check against naive substring search over randomized text) plus `RegexEvaluator`: refusal-phrase and secret/canary detection, custom pattern overrides, and instance isolation. |
| `tests/unit/test_onnx_evaluator.py` | `LocalONNXGuardEvaluator`: threshold handling, the mock classifier's short-circuit and escalation paths, `classifier_fn` injection, and graceful fallback when `onnxruntime`/a model file isn't available. |
| `tests/unit/test_llm_judge.py` | `LLMJudgeEvaluator`: structured JSON parsing, rubric injection, and retry-then-`UNCERTAIN` behavior on malformed JSON, empty responses, and transport errors. |
| `tests/unit/test_cascade_escalation.py` | `CascadeEvaluator`: short-circuiting at each tier, zero-external-call verification on Tier 1 matches, full three-tier fallback, and correctness under concurrent `evaluate()` calls on a shared instance. |
| `tests/unit/test_resumability_engine.py` | The pure campaign-resumability reconciliation logic against plain stand-in objects: turn-number gap detection (resuming from the first missing turn, not `max + 1`), composite-key (`target_id`, `strategy`, `seed_prompt`) collision handling, and every `ResumeDecision` branch. Has no SQLAlchemy dependency and always runs. |
| `tests/unit/test_database_models.py` | SQLAlchemy schema creation, `ON DELETE CASCADE` behavior through `DatabaseManager`'s per-connection pragma fix, the unique `(test_id, turn_number)` constraint, and the `MetricModel` one-to-one relationship. Requires `sqlalchemy` + `aiosqlite`; self-skips otherwise. |
| `tests/unit/test_repository.py` | `CampaignRepository`: campaign/test lifecycle, `find_test`/`list_incomplete_tests` natural-key and execution-state queries, turn/finding recording, metric accumulation via `upsert_metrics`, and (Phase 6) `list_recent_campaigns`'s ordering/limit/empty-database behavior. Requires `sqlalchemy` + `aiosqlite`; self-skips otherwise. |
| `tests/unit/test_attack_state.py` | `ConversationContext` memory (`add_turn`, `pop_last_turn`), the attack-tree node index (`add_node`, `path_to`, cyclic-parent-chain safety, `best_score`), and `score_from_evaluation`'s mapping from Phase 3's `Verdict`/confidence onto Phase 5's 0-10 attack-progress scale. |
| `tests/unit/test_attacker_agent.py` | `AttackerAgent`: structured JSON parsing, goal interpolation, conversation-history forwarding, and retry-then-`AttackerGenerationError` behavior on malformed JSON, empty responses, and missing required fields. |
| `tests/unit/test_crescendo_engine.py` | `CrescendoEngine.run()`: exactly one `AttackNode` yielded per turn (including the backtrack-turn regression case), state-rollback correctness (a backtracked turn's exchange is absent from what's next sent to the target), `REFUSED` vs `BACKTRACK` status selection based on remaining backtrack budget, success short-circuiting before `max_turns`, and graceful termination on attacker failure. |
| `tests/unit/test_tap_pruning.py` | `TAPEngine.execute_tree_search()`: pruning below/above the score threshold, multi-depth expansion (the loop-nesting regression case), returning the best partial path when nothing succeeds, and fault tolerance when an individual branch's attacker call fails via `asyncio.gather(return_exceptions=True)`. |
| `tests/unit/test_cli.py` | The `cyberjection` CLI end-to-end via `typer.testing.CliRunner`: `--help`, required-option enforcement, config/target error handling, quality-gate exit codes (pass/fail/threshold-fallback-to-campaign-config), SARIF/JSON/Markdown export flags (including relative-path-traversal rejection), the `export` command's format handling, `inspect`'s environment-unavailable and rendering paths (the latter via a monkeypatched `_inspect_async`), and (Phase 8) the `audit` command's default-flag behavior, `--deps`/`--fail-on-unavailable`, `--secrets` finding/clean paths, `--targets`' config-required and informational-only behavior, `--compliance`, and `--report` (including its own path-traversal rejection). |
| `tests/unit/test_sarif_exporter.py` | `SARIFReporter`: structural validation against a locally-authored minimal SARIF 2.1.0 schema, rule-catalog deduplication for a repeated `rule_id`, and threshold-relative severity levels (both regression coverage for bugs in the Phase 6 design spec's own sketch). |
| `tests/unit/test_exporters.py` | `JSONExporter` (summary block correctness, `Finding` round-trip via `model_validate`) and `MarkdownExporter` (pass/fail header, per-finding table rows, pipe-character escaping). |
| `tests/unit/test_quality_gate.py` | `resolve_threshold`'s CLI > config > default precedence (including that an explicit `0.0` at either level is not treated as "missing") and `evaluate_quality_gate`'s pass/fail/exactly-at-threshold decision, independent of any CLI or Typer machinery. |
| `tests/unit/test_rate_limiter.py` | `evaluate_dual_bucket` pure-function edge cases (empty bucket, exact-boundary requests, refill saturation, zero elapsed time, RPM-ok-but-TPM-short rejection, no-partial-debit-on-rejection) and `DistributedRateLimiter.acquire()` integration: capacity guards, actual TPM enforcement, shared state across two instances on the same Redis URL, and a 50-way concurrent `acquire()` race against a 10-unit bucket proving atomicity. |
| `tests/unit/test_retry.py` | `compute_backoff_delay`'s exponential growth, jitter injection (with a deterministic injected `rng`), capping, and input validation; `build_dead_letter_payload`'s JSON-serializability and field population. No Redis/Celery dependency. |
| `tests/unit/test_coordinator.py` | `DistributedClusterCoordinator`: abort broadcast reaching a subscribed listener, a pre-subscription broadcast being a silent no-op, channel isolation between differently-named coordinators on the same Redis instance, pubsub connection cleanup after listening (regression test for a connection leak in the design spec's own sketch), and `broadcast_if_failing`'s `Verdict.FAIL`-only trigger condition. |
| `tests/unit/test_distributed_tasks.py` | `execute_eval_turn_task`: successful completion, rate-limit enforcement, transient-failure retry-then-succeed, exhausted-retry `MaxRetriesExceededError`, retry count bounded by `MAX_RETRIES`, dead-letter-queue push on exhaustion (and never on success), and per-target rate-limiter instance caching. |
| `tests/unit/test_input_validation.py` | `assert_safe_output_path` (relative containment, absolute-path pass-through, `..` and symlink escape rejection), `assert_safe_target_url` (scheme/hostname/literal-IP rejection and the `allow_private_networks` opt-in), and `enforce_payload_size_limit` (byte-vs-character sizing, exact-boundary behavior). |
| `tests/unit/test_audit_log.py` | `AuditLogger`: hash-chain linkage across entries, metadata round-tripping, JSONL well-formedness, and thread-safe concurrent appends (200 entries from 10 threads, verified via `verify_chain`); `verify_chain`: clean-chain validation, tampered-entry detection at the correct index, and empty/missing-file handling. |
| `tests/unit/test_secrets_audit.py` | `scan_text_for_secrets` against every registered pattern (AWS keys, private key headers, Slack/GitHub tokens, generic API-key assignments) and placeholder-marker suppression; `scan_paths_for_secrets` (recursive walk, excluded-dir skipping, binary-file tolerance); `scan_campaign_config_for_hardcoded_secrets` (literal-vs-`${VAR}`-interpolated `api_key` values). |
| `tests/unit/test_dependency_audit.py` | `parse_pip_audit_json` against canned `pip-audit --format json` fixtures (single/multiple findings, missing fields, truncation, malformed input); `run_dependency_audit`'s real `source="unavailable"` fallback in this sandbox; `evaluate_dependency_gate`'s pass/fail decision across every `source` value and `fail_on_unavailable` setting. |
| `tests/unit/test_compliance.py` | Structural invariants of the real `CONTROL_REGISTRY` (unique ids, evidence required for `IMPLEMENTED`, notes required for `NOT_APPLICABLE`) plus `compliance_summary`/`generate_compliance_report` against both the real registry and small synthetic ones (grouping order, missing-evidence/notes rendering, multiline-note flattening). |
| `tests/unit/test_orchestrator.py` | `_build_cascade_evaluator`/`_build_strategy`/`_verdict_from_multi_turn` pure-function behavior; single-turn execution end-to-end against a monkeypatched `litellm.acompletion`; multi-turn dispatch/goal-resolution/turn-conversion against scripted `CrescendoEngine`/`TAPEngine` stand-ins; configuration-error and provider-failure handling (a failing test case never aborts the others); resumability's `SKIP_COMPLETE`/`RESUME`/no-manager paths (including that a `RESUME`'d test really does call the target again, as a fresh row); persistence wiring against a duck-typed fake repository; `max_concurrency` actually bounding in-flight test cases (a 12-vs-3 concurrency race, mirroring `test_rate_limiter.py`'s own atomicity test); and `execute_campaign`'s persistence-unavailable and `--resume`-without-persistence paths. |
| `tests/unit/test_registries.py` | The three Phase 10 subsystem registries (`cyberjection.attacks.registry`, `cyberjection.evaluators.registry`, `cyberjection.reporting.registry`): built-in alias presence, correct-class resolution, unknown-alias lookup errors, non-subclass/non-`export`-attribute rejection, alias-collision-with-a-different-class rejection, and idempotent re-registration -- the same property set `test_mutators.py::TestMutatorRegistry` already covers for the Phase 2 registry these three mirror. |
| `tests/unit/test_plugins.py` | `cyberjection.plugins.loader.discover_plugins`: successful load-and-register across all four plugin groups against fake `_FakeEntryPoint` objects, per-loaded-plugin metadata (group/alias/qualified_name/obj), non-fatal failure on a wrong-base-type plugin or a `load()` that raises (one bad plugin doesn't block the others in the same group), `strict=True` raising on first failure instead of collecting, an unknown plugin group, and `known_aliases_by_group`'s four-group shape and sorted output. |
| `tests/unit/test_api.py` | `cyberjection.api.asgi`: `Router` path-param matching (including that a param can't cross a `/` boundary, and that a more-specific route registered first wins), `Request.query_int`'s malformed-input fallback, ASGI `lifespan` startup/shutdown handshake, unmatched-route 404, handler-exception 500, and query-string parsing. `cyberjection.api.app`: `/api/health`, `/api/plugins` (built-in aliases present, empty discovery/failures), and the `/api/campaigns*` 503 "persistence unavailable" path (via a monkeypatched `_SQLALCHEMY_AVAILABLE`). Uses a hand-rolled ASGI test client (`_call_asgi_app`) rather than `httpx`/`starlette.testclient`, neither of which is a project dependency. |
| `tests/unit/test_api_persistence.py` | The same `/api/campaigns*` endpoints' happy path against a real in-memory database (`DatabaseManager.in_memory()`, wired into `build_app`'s `manager=` parameter): campaign listing, campaign detail with its tests, unknown-campaign 404, test detail with turns/metrics, and the "test id right, campaign id wrong" and unknown-test-id 404 cases. Requires `sqlalchemy` + `aiosqlite`; self-skips otherwise (kept in its own module, not a class inside `test_api.py`, specifically so the whole file module-skips the same way `test_database_models.py`/`test_repository.py` already do, rather than relying on a class-scoped fixture the offline test runner's fixture resolver doesn't collect). |
| `tests/conftest.py` | Shared fixtures: a temp-file YAML writer and an environment-cleaning fixture for tests that need to assert on missing variables. |

## Conventions

- The provider layer is tested by monkeypatching `litellm.acompletion`
  directly rather than hitting real APIs. Fixtures build a
  `SimpleNamespace` shaped like a LiteLLM response (`choices`, `usage`,
  `model`) so tests stay fast and deterministic.
- Async tests use `pytest-asyncio`; classes under test that are entirely
  async are marked with `@pytest.mark.asyncio` at the class level rather
  than repeating the marker per method.
- Concurrency and timing-sensitive tests (semaphore caps, retry counts,
  rate-limiter pacing) use small `backoff_base_seconds` values and
  generous tolerances to stay fast without becoming flaky.
- Tests that assert on internal state (e.g. `target._semaphore._value`)
  are intentional white-box checks confirming that permits are released
  correctly under both success and failure paths -- not just that the
  public API returns the right value.
- Phase 5's multi-turn engine tests (`test_crescendo_engine.py`,
  `test_tap_pruning.py`) use lightweight duck-typed test doubles for the
  target, evaluator, and attacker rather than real `LiteLLMTarget` /
  `CascadeEvaluator` / `AttackerAgent` instances, since the engines only
  call three narrow async methods on each (`generate_conversation`,
  `evaluate`, `generate_next_payload`). This keeps the engine-logic tests
  fast and focused on control flow, while `test_litellm_provider.py` and
  `test_attacker_agent.py` separately cover the real classes' own behavior
  in isolation.
- Phase 6's `test_cli.py` fixtures (`config_path`, `json_report`) are
  declared at module scope rather than nested inside a `Test*` class, even
  where they're only used by one class -- consistent, simple `@pytest.fixture`
  discovery. Prefer this shape for any new CLI test fixture.
- `test_cli.py` isolates `inspect`'s success path from needing a real
  SQLAlchemy database by monkeypatching `cyberjection.cli.main._inspect_async`
  itself, not just `_SQLALCHEMY_AVAILABLE` -- so the test exercises the
  command's own table-rendering logic without depending on `sqlalchemy`
  being installed at all.

## Adding a new provider or config field

1. Extend the relevant model in `cyberjection/config/schema.py`.
2. Add both a valid-input test and at least one boundary/invalid-input
   test in `tests/unit/test_schema_validation.py`.
3. If the field affects request construction or runtime behavior in
   `LiteLLMTarget`, add a corresponding case in
   `tests/unit/test_litellm_provider.py` that asserts on what was passed
   to the mocked `acompletion` call.
4. Update `docs/CONFIGURATION.md` with the new field.

## Adding a new mutator

1. Subclass `BaseMutator` in a new module under `cyberjection/mutators/`
   and implement `mutate(self, prompt: str) -> str`.
2. Register it with a short alias via the `@register_mutator("your_alias")`
   class decorator.
3. Import the new module from `cyberjection/mutators/__init__.py` so the
   registration side effect runs on package import.
4. If the mutator uses randomization, accept an optional `seed` parameter
   and draw from a private `random.Random(seed)` instance rather than the
   shared `random` module -- see `test_mutators.py::TestUnicodeZeroWidthMutator`
   for the reproducibility and global-state-isolation tests every
   randomized mutator should have an equivalent of.
5. Add transformation tests to `tests/unit/test_mutators.py` and a
   chaining case to `tests/unit/test_mutator_pipeline.py` if the ordering
   relative to other mutators matters.

## Adding a new attack strategy

1. Subclass `BaseStrategy` in a new module under `cyberjection/attacks/`
   and implement `async execute(self, target, seed_prompt, context) ->
   SingleTurnResult`, calling `self._apply_mutations(framed_prompt)` before
   dispatch and `self._to_result(...)` to build the return value.
2. Add a case to `tests/unit/test_single_turn_attacks.py` that mocks
   `litellm.acompletion` and asserts on both the framed/mutated prompt sent
   to the target and the populated `SingleTurnResult` fields.

## Adding a new evaluator tier or pattern

1. Subclass `BaseEvaluator` in a new module under `cyberjection/evaluators/`
   and implement `async evaluate(self, prompt_sent, response_text) ->
   EvaluationOutcome`. Return `Verdict.UNCERTAIN` for "I can't tell" rather
   than guessing -- that's the signal the cascade escalates on.
2. If the tier holds no state that would race under concurrent
   `evaluate()` calls on a shared instance, don't add any (see
   `CascadeEvaluator`, which derives its telemetry from the returned
   outcome instead of instance attributes for exactly this reason).
3. To add a new Tier 1 pattern, prefer editing
   `cyberjection/evaluators/regexes/refusal_patterns.txt` (literal
   substrings) or `secrets.txt` (regexes) over hardcoding in `regex.py`,
   and add a case to `tests/unit/test_regex_evaluator.py`. Check any new
   regex for catastrophic-backtracking risk (no nested unbounded
   quantifiers) since Tier 1 is meant to stay sub-millisecond.
4. Add a case to the relevant test file, and a cascade-level case to
   `tests/unit/test_cascade_escalation.py` if the change affects
   escalation behavior (e.g. a new short-circuit condition).

## Adding a persistence model or repository method

1. Add or change the SQLAlchemy model in `cyberjection/persistence/models.py`,
   then update `alembic/versions/0001_initial_schema.py` (or add a new
   revision) to match -- the migration is hand-authored, not
   autogenerated, so the two must be kept in sync by hand.
2. Add the corresponding `CampaignRepository` method in
   `cyberjection/persistence/repository.py`, following the existing
   commit-immediately convention (see the module docstring).
3. Add a case to `tests/unit/test_database_models.py` or
   `tests/unit/test_repository.py`, using `DatabaseManager.in_memory()`.
4. If the change affects what `build_resume_map`/`reconcile_test_state`
   reconciles (`cyberjection/persistence/resumability.py`), keep that
   module's functions free of any SQLAlchemy import -- they should only
   read duck-typed attributes off whatever's passed in -- and add a case to
   `tests/unit/test_resumability_engine.py` using a plain
   `types.SimpleNamespace` stand-in, so the test keeps running without
   SQLAlchemy installed.

## Adding a new multi-turn attack engine

1. Implement the engine in a new module under `cyberjection/attacks/`,
   taking a `CascadeEvaluator` and an `AttackerAgent` (or any object
   duck-typing their `.evaluate()` / `.generate_next_payload()` methods)
   rather than constructing them internally, so tests can substitute fast
   doubles.
2. Convert evaluator output to attack-progress terms via
   `cyberjection.attacks.state.score_from_evaluation` rather than
   inventing a second conversion -- see that function's docstring for why
   Phase 3's `Verdict`/confidence and Phase 5's 0-10 score/`is_refusal`
   shapes don't line up on their own.
3. Record every explored state as an `AttackNode` via
   `ConversationContext.add_node`, linking `parent_id` correctly across any
   backtracking or branch-pruning the engine does, so `path_to()` can
   reconstruct a coherent trajectory afterward.
4. Add a dedicated test module using the `FakeTarget` / `FakeEvaluator` /
   `ScriptedAttacker` (or equivalent) pattern established in
   `test_crescendo_engine.py` and `test_tap_pruning.py`.

## Adding a new CLI command or report exporter

1. For a new CLI command, add a `@app.command("name")`-decorated function
   to `cyberjection/cli/main.py`. Keep the command function itself thin:
   argument parsing and `console.print`/`typer.Exit` calls only, with any
   real logic factored into a plain, separately-testable function or
   `async def` helper (see `_resolve_target`, `_inspect_async`) -- the
   pattern that keeps `test_cli.py` able to assert on exit codes and
   output without needing to duck-type around Typer/Click internals.
2. For a new report format, add an `export(findings: List[Finding],
   output_path: Path, *, threshold: float = 7.0) -> None` static method to
   a class in `cyberjection/reporting/exporters.py` (or a new module next
   to `sarif.py`), consuming `Finding` -- never a raw `dict` -- so it stays
   interchangeable with the other exporters from the CLI's point of view.
3. Add exit-code and output-content assertions to `tests/unit/test_cli.py`
   if the change is CLI-facing; add format-specific structural assertions
   to `tests/unit/test_sarif_exporter.py` / `test_exporters.py` (or an
   equivalent new file) for a new exporter itself.
4. If the change affects the pass/fail decision, add a case to
   `tests/unit/test_quality_gate.py` rather than only testing it through
   the CLI -- `evaluate_quality_gate`/`resolve_threshold` are meant to stay
   testable independent of Typer.

## Adding a new distributed task or coordination signal

1. Define the task in `cyberjection/distributed/tasks.py` with
   `@celery_app.task(bind=True, max_retries=..., default_retry_delay=...)`,
   calling `DistributedRateLimiter.acquire()` (via the `_get_rate_limiter`
   cache, not a fresh instance per call) before any external API request.
2. Wrap the task body's real work in a `try`/`except`, computing a
   `compute_backoff_delay(self.request.retries)` countdown and calling
   `raise self.retry(exc=exc, countdown=countdown)` on transient failure.
   Catch `MaxRetriesExceededError` around that `self.retry()` call and
   push to the dead-letter queue via `push_to_dead_letter_queue` before
   re-raising -- see `execute_eval_turn_task` for the exact shape.
3. If the new logic has a pure-math or pure-data-shape component (a new
   backoff variant, a new DLQ payload field), factor it into
   `cyberjection/distributed/retry.py` as a standalone function so it can
   be hard-tested without Celery or Redis, following `compute_backoff_delay`
   and `build_dead_letter_payload`.
4. For a new cluster-wide coordination signal (beyond abort), add a method
   to `DistributedClusterCoordinator` following `broadcast_abort`'s
   publish-a-JSON-payload shape, and a corresponding `listen_for_*` that
   subscribes, `try`/`finally`-cleans-up the pubsub connection, and returns
   the parsed payload -- see the module docstring for why Pub/Sub (not the
   Celery queue itself) is the right primitive for a broadcast.
5. Add test coverage to `tests/unit/test_distributed_tasks.py` or
   `tests/unit/test_coordinator.py` using a `monkeypatch`-installed stub for
   whatever async work the task/signal wraps (see `_install_failing_stub`
   in `test_distributed_tasks.py`), so retry/backoff/DLQ paths can be
   exercised deterministically without waiting on real countdowns.

## Adding a new dashboard API endpoint

1. Add an `async def handler(request: Request) -> Response` closure
   inside `build_app` in `cyberjection/api/app.py`, following the
   existing handlers' shape: resolve the persistence manager via
   `_get_manager()` and return `_unavailable()` if it's `None`, otherwise
   open a session, query through `CampaignRepository`, and return
   `JSONResponse(...)`.
2. Register the route via `router.add_route("GET", "/api/your/{path}",
   handler)` in `build_app`, before any less-specific route that could
   also match the same path prefix (see `cyberjection.api.asgi.Router`'s
   docstring).
3. Add cases to `tests/unit/test_api.py` for the persistence-unavailable
   path (no `sqlalchemy` needed) and to `tests/unit/test_api_persistence.py`
   for the real-database happy path, following the `seeded_app` fixture
   pattern in the latter.
4. If the new endpoint's response shape is meant for the dashboard to
   consume, add the matching TypeScript interface to
   `apps/dashboard/src/types.ts` and a fetch function to
   `apps/dashboard/src/api/client.ts`.

## Adding a new plugin group

Phase 10 ships exactly four plugin groups (mutators, strategies,
evaluators, exporters) because those are the four extension points that
already had a subsystem registry before plugins existed. Adding a fifth
kind of pluggable thing means, in order: (1) build the subsystem registry
for it first, mirroring `cyberjection.mutators.registry`'s
register/get/list/idempotent-reregistration shape and its
`_reset_registry_for_tests`/`_restore_registry_for_tests` test helpers;
(2) add the new group name to `cyberjection.plugins.base.ALL_PLUGIN_GROUPS`
and a registrar entry to `cyberjection.plugins.loader._REGISTRARS`; (3)
add the group to `cyberjection.plugins.registry._ALIAS_LISTERS`; (4) add
test coverage to `tests/unit/test_registries.py` (the new registry) and
`tests/unit/test_plugins.py` (discovery through the new group). Do not
introduce a plugin-specific registry that duplicates what the subsystem
registry already tracks -- see `docs/ARCHITECTURE.md`'s Phase 10 section
for why.
