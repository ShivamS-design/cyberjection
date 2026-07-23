# Contributing

## Development setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
pytest tests/unit/ -v
mypy cyberjection/config/ cyberjection/providers/
pytest tests/unit/ --cov=cyberjection --cov-report=term-missing
```

All new code should have unit test coverage. Config schema changes need a
corresponding entry in `docs/CONFIGURATION.md`.

## Style

- Type hints on all public functions and methods.
- `from __future__ import annotations` at the top of every module.
- Docstrings on public classes and functions explaining intent, not just
  restating the signature.
- Keep provider-specific exception handling inside
  `cyberjection/providers/`; callers elsewhere should only ever see
  `cyberjection.utils.exceptions.CyberjectionException` subclasses.

## Project structure

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full layered
design and the phase roadmap. Each phase adds a self-contained subsystem;
avoid reaching ahead into a future phase's modules from current-phase code.

## Commit messages

Keep commits scoped to one logical change. Reference the affected module
path in the summary line, e.g. `providers: add token-bucket rate limiter`.
