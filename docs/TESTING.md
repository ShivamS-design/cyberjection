# Testing guide

## Running the suite

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v
mypy cyberjection/config/ cyberjection/providers/
pytest tests/unit/ --cov=cyberjection --cov-report=term-missing
```

## Layout

| File | Covers |
|---|---|
| `tests/unit/test_config_loader.py` | Environment-variable expansion (including the single-pass, non-recursive guarantee), YAML parsing errors, missing/malformed files, and end-to-end loading of `examples/quickstart.yaml`. |
| `tests/unit/test_schema_validation.py` | Field-level constraints (ranges, required fields), duplicate-id rejection, cross-reference validation between tests and their targets/strategies, and independence of `default_factory` fields across instances. |
| `tests/unit/test_litellm_provider.py` | The provider adapter: request construction, retry/backoff behavior, exception classification, concurrency limits, cancellation handling, and the token-bucket rate limiter. |
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
