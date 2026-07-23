# Cyberjection

Cyberjection is an enterprise-grade, asynchronous LLM red-teaming and
security orchestration framework. It automates adversarial prompt
execution, multi-turn stateful attacks, and cost-efficient safety
evaluation against large language models, RAG pipelines, and autonomous
agents.

Full documentation lives in [`docs/`](docs/):

- [Architecture](docs/ARCHITECTURE.md) - system design and component layout
- [Configuration reference](docs/CONFIGURATION.md) - the YAML campaign schema
- [Testing guide](docs/TESTING.md) - running and extending the test suite
- [Changelog](CHANGELOG.md) - release notes per phase

## Status

Phase 1 of the project roadmap is implemented: **Core Async Architecture,
Declarative Configuration & Target Abstraction Gateway**. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#roadmap) for the full 10-phase
plan and what ships in each stage.

## Features (Phase 1)

- Declarative YAML campaign configuration with `${VAR}` / `${VAR:-default}`
  environment-variable expansion, so secrets never live in version-controlled
  config files.
- Strict schema validation (targets, strategies, assertions, test cases,
  campaigns) with cross-reference checks between targets/strategies and the
  tests that use them.
- A universal target gateway built on LiteLLM, giving access to 100+ model
  providers (OpenAI, Anthropic, Bedrock, Azure, Ollama, vLLM, Gemini, custom
  HTTP endpoints) through one interface.
- Per-target rate limiting: a token-bucket limiter paces requests to the
  configured `requests_per_second`, and a concurrency semaphore caps
  simultaneous in-flight calls at `burst`.
- Automatic retry with exponential backoff on transient failures
  (rate limits, timeouts), and fast failure on non-transient connection
  errors.
- Normalized usage metrics (prompt/completion tokens, latency) on every
  target call.

## Installation

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quickstart

```bash
cp .env.example .env   # fill in OPENAI_API_KEY, etc.
export $(grep -v '^#' .env | xargs)
```

```python
from cyberjection.config.loader import load_config

config = load_config("examples/quickstart.yaml")
print(config.name, [t.id for t in config.targets])
```

```python
import asyncio
from cyberjection.providers.litellm_provider import LiteLLMTarget

async def main():
    target = LiteLLMTarget(config.targets[0])
    response = await target.generate("Hello!")
    print(response.content, response.metrics)

asyncio.run(main())
```

## Project layout

```
cyberjection/
├── cyberjection/
│   ├── config/       # schema.py, loader.py
│   ├── providers/    # base.py, litellm_provider.py
│   └── utils/         # exceptions.py, context.py
├── examples/
│   └── quickstart.yaml
├── tests/
│   └── unit/
├── docs/
├── .env.example
└── pyproject.toml
```

## Testing

```bash
pytest tests/unit/ -v
mypy cyberjection/config/ cyberjection/providers/
pytest tests/unit/ --cov=cyberjection --cov-report=term-missing
```

See [`docs/TESTING.md`](docs/TESTING.md) for what each test module covers
and the conventions used for mocking the provider layer.

## License

Apache License 2.0. See [LICENSE](LICENSE).
