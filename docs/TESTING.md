# Testing guide

## Running the suite

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v
mypy cyberjection/config/ cyberjection/providers/ cyberjection/mutators/ cyberjection/attacks/ cyberjection/evaluators/
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
| `tests/unit/test_repository.py` | `CampaignRepository`: campaign/test lifecycle, `find_test`/`list_incomplete_tests` natural-key and execution-state queries, turn/finding recording, and metric accumulation via `upsert_metrics`. Requires `sqlalchemy` + `aiosqlite`; self-skips otherwise. |
| `tests/unit/test_attack_state.py` | `ConversationContext` memory (`add_turn`, `pop_last_turn`), the attack-tree node index (`add_node`, `path_to`, cyclic-parent-chain safety, `best_score`), and `score_from_evaluation`'s mapping from Phase 3's `Verdict`/confidence onto Phase 5's 0-10 attack-progress scale. |
| `tests/unit/test_attacker_agent.py` | `AttackerAgent`: structured JSON parsing, goal interpolation, conversation-history forwarding, and retry-then-`AttackerGenerationError` behavior on malformed JSON, empty responses, and missing required fields. |
| `tests/unit/test_crescendo_engine.py` | `CrescendoEngine.run()`: exactly one `AttackNode` yielded per turn (including the backtrack-turn regression case), state-rollback correctness (a backtracked turn's exchange is absent from what's next sent to the target), `REFUSED` vs `BACKTRACK` status selection based on remaining backtrack budget, success short-circuiting before `max_turns`, and graceful termination on attacker failure. |
| `tests/unit/test_tap_pruning.py` | `TAPEngine.execute_tree_search()`: pruning below/above the score threshold, multi-depth expansion (the loop-nesting regression case), returning the best partial path when nothing succeeds, and fault tolerance when an individual branch's attacker call fails via `asyncio.gather(return_exceptions=True)`. |
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
