# Testing guide

## Running the suite

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v
mypy cyberjection/config/ cyberjection/providers/ cyberjection/mutators/ cyberjection/attacks/
pytest tests/unit/ --cov=cyberjection --cov-report=term-missing
```

To run only the Phase 2 suite:

```bash
pytest tests/unit/test_mutators.py tests/unit/test_mutator_pipeline.py tests/unit/test_single_turn_attacks.py -v
```

## Layout

| File | Covers |
|---|---|
| `tests/unit/test_config_loader.py` | Environment-variable expansion (including the single-pass, non-recursive guarantee), YAML parsing errors, missing/malformed files, and end-to-end loading of `examples/quickstart.yaml`. |
| `tests/unit/test_schema_validation.py` | Field-level constraints (ranges, required fields), duplicate-id rejection, cross-reference validation between tests and their targets/strategies, and independence of `default_factory` fields across instances. |
| `tests/unit/test_litellm_provider.py` | The provider adapter: request construction, retry/backoff behavior, exception classification, concurrency limits, cancellation handling, and the token-bucket rate limiter. |
| `tests/unit/test_mutators.py` | Every concrete mutator's transformation logic, seeded reproducibility of the randomized mutators, and the alias registry (registration, collision handling, unknown-alias lookup). |
| `tests/unit/test_mutator_pipeline.py` | `MutatorPipeline` chaining order, empty-pipeline passthrough, and that reordering mutators changes the output. |
| `tests/unit/test_single_turn_attacks.py` | `DirectPromptInjectionStrategy`, `JailbreakStrategy`, and `SystemPromptExtractionStrategy` executed against a mocked `LiteLLMTarget`: framing, mutation-pipeline application, and `SingleTurnResult` population. |
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
