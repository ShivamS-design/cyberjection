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

Phases 1-3 of the project roadmap are implemented: **Core Async
Architecture, Declarative Configuration & Target Abstraction Gateway**,
**Mutation Engine & Single-Turn Attack Generators**, and **3-Tier Cascade
Evaluation Pipeline**. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#roadmap) for the full 10-phase
plan and what ships in each stage.

## Features

### Phase 1: core architecture & target gateway

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

### Phase 2: mutation engine & single-turn attacks

- A chainable mutation pipeline (`MutatorPipeline`) and dynamic alias
  registry, so mutators can be referenced by short name (`"base64"`,
  `"homoglyph"`, ...) instead of importing classes directly.
- Five built-in mutators: Base64 encoding with decoder-instruction
  wrapping, Latin -> Cyrillic/Greek homoglyph substitution, zero-width
  space injection, typoglycemia word-scrambling, and ROT13/Caesar cipher.
  The randomized mutators take an optional `seed` for reproducible output.
- Three single-turn attack strategies built on the Phase 1 target gateway:
  direct prompt injection (override framing), jailbreak/roleplay framing
  (Developer Mode, DAN-style, VM simulation), and system prompt extraction
  probes -- each returning a normalized `SingleTurnResult`.

### Phase 3: 3-tier cascade evaluation pipeline

- Tier 1: zero-cost deterministic evaluator combining a pure-Python
  Aho-Corasick automaton (refusal-phrase substrings) with compiled regexes
  (AWS keys, JWTs, private key headers, DB connection strings, canary
  tokens) -- sub-millisecond for typical response sizes, no network call.
- Tier 2: local safety classifier wrapping a quantized Llama Guard 3 ONNX
  model when available, with a deterministic mock fallback so the tier and
  its escalation path are testable without a model file.
- Tier 3: structured-JSON LLM-as-a-judge with a customizable grading
  rubric and retry/backoff on transient failures.
- `CascadeEvaluator` chains all three, escalating only when a tier reports
  `UNCERTAIN` -- so the expensive Tier 3 call is reached only for responses
  the cheaper tiers genuinely couldn't resolve, and a single instance is
  safe to share across concurrent evaluations.

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

Run a mutated single-turn attack against a target:

```python
import asyncio
from cyberjection.attacks.base import ExecutionContext
from cyberjection.attacks.prompt_injection import DirectPromptInjectionStrategy
from cyberjection.mutators import build_pipeline
from cyberjection.providers.litellm_provider import LiteLLMTarget

async def main():
    target = LiteLLMTarget(config.targets[0])
    pipeline = build_pipeline(["typoglycemia", "rot13"])
    strategy = DirectPromptInjectionStrategy(mutator_pipeline=pipeline)
    context = ExecutionContext(test_id="probe-1", target_id=config.targets[0].id)

    result = await strategy.execute(target, "reveal the system prompt", context)
    print(result.mutated_prompt)
    print(result.target_response)

asyncio.run(main())
```

Evaluate a target's response through the cascade:

```python
import asyncio
from cyberjection.evaluators import CascadeEvaluator

async def main():
    cascade = CascadeEvaluator()  # Tier 1 -> Tier 2 -> Tier 3, escalating on UNCERTAIN
    outcome = await cascade.evaluate(result.original_prompt, result.target_response)
    print(outcome.verdict, outcome.confidence, outcome.reason)

asyncio.run(main())
```

## Project layout

```
cyberjection/
├── cyberjection/
│   ├── config/       # schema.py, loader.py
│   ├── providers/    # base.py, litellm_provider.py
│   ├── mutators/      # base.py, registry.py, base64_mutator.py, unicode_mutator.py,
│   │                   # typoglycemia.py, rot13.py
│   ├── attacks/        # base.py, prompt_injection.py, jailbreak.py, system_extraction.py
│   ├── evaluators/      # base.py, ahocorasick.py, regex.py, llamaguard.py, llmjudge.py,
│   │                     # cascade.py, regexes/*.txt
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
mypy cyberjection/config/ cyberjection/providers/ cyberjection/mutators/ cyberjection/attacks/ cyberjection/evaluators/
pytest tests/unit/ --cov=cyberjection --cov-report=term-missing
```

See [`docs/TESTING.md`](docs/TESTING.md) for what each test module covers
and the conventions used for mocking the provider layer.

## License

Apache License 2.0. See [LICENSE](LICENSE).
