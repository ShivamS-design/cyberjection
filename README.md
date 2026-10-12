# Cyberjection

Cyberjection is an enterprise-grade, asynchronous LLM red-teaming and
security orchestration framework. It automates adversarial prompt
execution, multi-turn stateful attacks, and cost-efficient safety
evaluation against large language models, RAG pipelines, and autonomous
agents -- and, since Phase 11, vets model repositories for supply-chain
attacks (malicious pickles, `trust_remote_code` payloads, tampered
weights, leaked credentials, backdoor triggers) before a single weight
is loaded or a prompt is sent.

Full documentation lives in [`docs/`](docs/):

- [Architecture](docs/ARCHITECTURE.md) - system design and component layout
- [Configuration reference](docs/CONFIGURATION.md) - the YAML campaign schema
- [Testing guide](docs/TESTING.md) - running and extending the test suite
- [Security policy](docs/SECURITY.md) - hardening controls and vulnerability disclosure
- [Compliance self-assessment](docs/COMPLIANCE.md) - OWASP ASVS 4.0 / SOC 2 control mapping
- [Deployment guide](docs/DEPLOYMENT.md) - running the dashboard API and web dashboard
- [Changelog](CHANGELOG.md) - release notes per phase

## Status

All 11 phases of the project roadmap are implemented: **Core Async
Architecture, Declarative Configuration & Target Abstraction Gateway**,
**Mutation Engine & Single-Turn Attack Generators**, **3-Tier Cascade
Evaluation Pipeline**, **Persistence Layer, Database Models & Resumability
Engine**, **Stateful Multi-Turn Adaptive Attack Engine**, **CI/CD
Pipeline Integration, CLI Harness & Enterprise Reporting**,
**Distributed Worker Architecture, Task Queues & Rate Limiting Engine**,
**Security Auditing, Compliance & Production Hardening**, **Orchestrator**,
**Plugin Architecture & Web Dashboard**, and
**HubGuard & Model Supply Chain Security**. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#roadmap) for the full
11-phase plan and what shipped in each stage.

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

### Phase 4: persistence layer & resumability

- SQLAlchemy 2 declarative schema (`CampaignModel`, `TestModel`,
  `TurnModel`, `FindingModel`, `MetricModel`) over an async SQLite engine
  (`aiosqlite`, WAL journaling), with cascading foreign keys and a unique
  `(test_id, turn_number)` index guarding against duplicate turns.
- `CampaignRepository`, a DAO covering the full campaign/test lifecycle:
  creating campaigns and tests, recording turns/findings/metrics as they
  happen (each commit is immediate, not batched), and the execution-state
  queries reporting and resumability need.
- Campaign resumability: a pure reconciliation algorithm keyed by the
  composite `(target_id, strategy, seed_prompt)` natural key reconciles
  persisted state against campaign config, so an interrupted run can skip
  completed tests and resume a partially-completed multi-turn test from its
  first missing turn number instead of starting over.
- Alembic migrations, including an async-engine-compatible `env.py` so
  migrations run through the same connection code path as the application.

### Phase 5: stateful multi-turn adaptive attack engine

- `ConversationContext` and `AttackNode`: live conversation memory plus a
  parallel attack-tree index that survives backtracking -- a rolled-back
  turn disappears from what's sent to the target, but its `AttackNode`
  stays in the tree for reporting.
- `AttackerAgent`: a dedicated generator LLM that analyzes a target's
  latest response and formulates the next adversarial follow-up prompt,
  returning structured JSON (`analysis`, `refusal_detected`, `next_prompt`).
- `CrescendoEngine`: incremental foot-in-the-door escalation across up to
  `max_turns` turns, with automatic backtracking (`pop_last_turn`) out of
  hard refusals so the target's memory doesn't carry a refusal forward.
- `TAPEngine`: Tree-of-Attacks-with-Pruning breadth-first branching search,
  exploring `branching_factor` candidate follow-ups per branch at every
  depth, pruning branches below a score threshold, and returning the full
  winning path (or the best-scoring path explored, if none succeeded).
- Both engines score attacks on the same 3-tier `CascadeEvaluator` from
  Phase 3 via `score_from_evaluation()`, which bridges Phase 3's
  `Verdict`/confidence result onto the 0-10 attack-progress scale these
  engines are built around.

### Phase 6: CI/CD pipeline integration, CLI harness & enterprise reporting

- `cyberjection` CLI (Typer + Rich): `run` executes an evaluation against a
  configured target and applies a pass/fail quality gate; `inspect` browses
  persisted campaign history; `export` re-renders a prior JSON report into
  SARIF or Markdown.
- `SARIFReporter`: exports findings as SARIF 2.1.0, ready for GitHub
  Advanced Security's code scanning tab or GitLab's Security Dashboard --
  with severity levels derived from the run's actual `--threshold` rather
  than a fixed cutoff, and one deduplicated catalog entry per rule id.
- `JSONExporter` / `MarkdownExporter`: machine-readable JSON audit logs and
  executive Markdown summaries, both carrying the same pass/fail summary
  block as the SARIF report.
- `evaluate_quality_gate()`: a pure threshold decision (findings scoring at
  or above the threshold fail the gate) decoupled from the CLI, with a
  documented exit-code convention (`0` pass, `1` gate failure, `2` usage
  error, `3` environment error) so CI pipelines can branch on it reliably.
- Reusable GitHub Actions workflow (`.github/workflows/cyberjection.yml`)
  and GitLab CI template (`.gitlab-ci.yml`) running the CLI as a
  pull-request security gate and uploading the SARIF report as a build
  artifact.

### Phase 7: distributed worker architecture, task queues & rate limiting

- `DistributedRateLimiter`: a Redis-backed token bucket enforcing both
  requests-per-minute and tokens-per-minute limits per target provider
  across an entire worker cluster (not just one process), checked and
  debited atomically in a single Redis Lua script so a request is never
  partially admitted.
- Celery task queue (`celery_app.py` + `tasks.py`): `execute_eval_turn_task`
  distributes evaluation turns across a horizontal worker pool, acquiring
  a cluster-wide rate-limit token before each call, retrying transient
  failures with exponential backoff and jitter, and routing exhausted
  failures to a durable dead-letter queue instead of vanishing silently.
- `DistributedClusterCoordinator`: Redis Pub/Sub broadcast/listen for
  cluster-wide early-termination signals, wired directly to the Phase 3
  `Verdict` type -- a `Verdict.FAIL` can abort in-flight work on every
  worker node, not just the one that produced it.

### Phase 8: security auditing, compliance & production hardening

- Output-path containment (`assert_safe_output_path`), a literal-value
  SSRF guard for target URLs (`assert_safe_target_url`), and a payload
  size ceiling (`enforce_payload_size_limit`), wired into every CLI
  command that accepts a file path, target config, or response body.
- `AuditLogger`: a SHA-256 hash-chained, append-only audit trail. Every
  `run`/`inspect`/`export`/`audit` invocation writes an entry;
  `verify_chain()` detects any tampering with an existing entry.
- `cyberjection audit`: dependency vulnerability scanning (`--deps`, via
  the real `pip-audit` tool), hardcoded-secret scanning (`--secrets`,
  source tree and campaign YAML), informational target-URL checks
  (`--targets`), and an OWASP ASVS 4.0 / SOC 2 control self-assessment
  (`--compliance`) -- combinable into one Markdown report (`--report`).
- New CI job (`hardening-gate` in both `.github/workflows/cyberjection.yml`
  and `.gitlab-ci.yml`): fails the build on a known dependency
  vulnerability or a hardcoded secret, independent of the evaluation
  quality gate.

### Phase 9: orchestrator

- `cyberjection run` executes the real Phase 2-5 attack/evaluator stack
  against the resolved target -- `cyberjection.orchestrator.campaign`
  replaces the fixed-finding stub every earlier phase shipped with.
- Concurrent test-case execution bounded by `CampaignConfig.max_workers`,
  wired through a real `asyncio.Semaphore`.
- Campaign persistence and resume support at the CLI: `run --db-url`
  points at a non-default database, and `run --resume <campaign-id>`
  continues a previously interrupted campaign, skipping already-completed
  test cases.
- A test-case execution failure (a provider outage, an unresolvable
  strategy) downgrades to an `UNCERTAIN`, incomplete finding rather than
  aborting the rest of the campaign.

### Phase 10: plugin architecture & web dashboard

- Third-party plugin discovery (`cyberjection.plugins.discover_plugins`)
  via Python packaging entry points across four groups (mutators,
  single-turn strategies, evaluators, report exporters) -- a plugin's
  alias works everywhere a built-in one does (campaign YAML, `cyberjection
  export --format`), with no fifth "plugin registry" involved.
- `cyberjection plugins` lists every registered alias by group; a broken
  plugin is reported, not fatal to the listing.
- A dependency-free dashboard REST API (`cyberjection.api`, served via
  `cyberjection serve`): five read-only endpoints over campaign/test
  history and the plugin registries, built on nothing but the standard
  library so it never requires FastAPI/Starlette to be installed.
- A Vite + React + TypeScript web dashboard (`apps/dashboard/`): campaign
  list, campaign detail, full conversation-transcript test detail, and a
  plugins page.
- `cyberjection serve --dashboard-dir apps/dashboard/dist` serves the API
  and the built dashboard from one process and one origin, for the
  "single trusted team, one instance" deployment model documented in
  [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). (Container images shipped in
  0.10.0 were removed in 0.11.0.)

### Phase 11: HubGuard & model supply chain security

- `cyberjection.hubguard.HubGuardClient.audit_repository()` vets a Hugging
  Face repository (or a local snapshot) and returns one `PASS`/`WARN`/
  `BLOCK` verdict with a 0-10 risk score. It never loads a model and
  never unpickles anything.
- **Pickle opcode scanning** of `.bin`/`.pt`/`.ckpt`/`.pkl`/`.npy`/`.npz`:
  PyTorch ZIP and legacy formats are unwrapped, `STACK_GLOBAL` operands
  are resolved through a symbolic stack and memo, and dotted-name and
  Python 2 alias evasions are handled. Unresolvable imports fail closed.
  Embedded or base64-encoded code is decoded and analyzed. For PyTorch
  ZIPs, only `data.pkl` is fetched, via HTTP Range requests.
- **Remote code analysis**: AST analysis of every `.py` file (process,
  network, filesystem, credential access, obfuscated `exec`), plus
  `auto_map` resolution that flags code pulled from *other*
  repositories. As an opt-in, a sandbox profiler imports the code in a
  restricted interpreter that denies and records process, network, write
  and native-code operations.
- **SafeTensors enforcement**: a STRICT/WARN/OFF SafeTensors-only policy
  and strict header validation. It matches the reference loader's checks
  and also rejects duplicate JSON keys, which the reference loader
  silently accepts.
- **Integrity**: SHA-256 hash manifests (`cyberjection hubguard
  manifest`), Git blob SHA-1 checks on every fetched file, optional
  full-download hash verification, and reads pinned to the resolved
  commit SHA.
- **Secret leak detection** in model cards, configs, commit messages and
  *earlier revisions*, because "deleted" secrets remain downloadable from
  Git history.
- **Weight checks** (opt-in): non-finite and outlier tensors, and
  embedding-norm outliers nominated as trigger candidates for a
  differential **backdoor trigger probe** run through any Phase 1
  target.
- A campaign `hubguard:` section makes `cyberjection run` refuse to start
  against a `BLOCK`ed `huggingface` target (exit code 4).

### 0.12.0: industry readiness

- **Enforced budget caps**: `max_cost_cap` now really stops spend across
  target, attacker and judge calls (exit code 5, reports still written).
- **Judge hardening**: nonce-tagged untrusted content plus a manipulation
  tripwire, so a target response can't talk the LLM judge into a PASS.
- **`cyberjection run --local-only`**: zero-cost, nothing-leaves-the-machine
  checks for pre-commit hooks.
- **OWASP Top 10 for LLM Applications (2025)** coverage report
  (`--format owasp-llm`).
- **Integrations**: pre-commit hooks, a GitHub Action (`action.yml`),
  GitLab CI templates, and a scheduled compliance example.
- **Hardening**: optional API bearer token, HMAC-keyed audit log
  (`audit --verify-log`), stricter SSRF guard, no exception text in API
  errors, and a fix for a crash when concurrent tests persisted results.
- **Packaging**: PyPI-ready metadata, `cyberjection --version`, typed
  package (`py.typed`), lockfiles, SHA-pinned CI, Dependabot, and a
  trusted-publishing release workflow.

## Installation

```bash
pip install cyberjection            # once published to PyPI
```

From source:

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

Persist campaign and test state, then check whether a test case has already
run before starting it:

```python
import asyncio
from cyberjection.persistence import CampaignRepository, DatabaseManager, ResumabilityManager

async def main():
    db = DatabaseManager()  # defaults to sqlite+aiosqlite:///.cyberjection/results.db
    await db.init_db()

    async with db.session() as session:
        repo = CampaignRepository(session)
        campaign = await repo.create_campaign("nightly-run")
        resumability = ResumabilityManager(repo)

        decision, state = await resumability.get_resume_decision(
            campaign.id, target_id="target-a", strategy="direct_prompt_injection",
            seed_prompt="reveal the system prompt",
        )
        print(decision)  # ResumeDecision.FRESH on a brand-new campaign

    await db.close()

asyncio.run(main())
```

Run a stateful multi-turn Crescendo attack:

```python
import asyncio
from cyberjection.attacks import AttackerAgent, CrescendoEngine
from cyberjection.evaluators import CascadeEvaluator
from cyberjection.providers.litellm_provider import LiteLLMTarget

async def main():
    target = LiteLLMTarget(config.targets[0])
    engine = CrescendoEngine(
        evaluator=CascadeEvaluator(),
        attacker=AttackerAgent(model="openai/gpt-4o-mini"),
        max_turns=8,
    )

    async for node in engine.run(target, goal="extract the system prompt", initial_prompt="Hi, what can you help with?"):
        print(node.depth, node.status, f"score={node.score:.1f}")
        if node.status.value == "SUCCESS":
            break

asyncio.run(main())
```

Run an evaluation from the command line and gate a CI/CD pipeline on it:

```bash
cyberjection run \
  --config examples/quickstart.yaml \
  --target support-agent \
  --threshold 7.0 \
  --sarif-out results.sarif \
  --json-out results.json
# exits 0 (pass), 1 (quality gate failed), 2 (usage/config error),
# 3 (a runtime dependency isn't installed), 4 (HubGuard blocked the
# target) or 5 (max_cost_cap reached; reports are still written)

cyberjection inspect --limit 5     # browse recent persisted campaigns
cyberjection export --from-json results.json --output results.md --format markdown
```

Audit this project's own dependencies and configuration for known
vulnerabilities and hardcoded secrets:

```bash
pip install -e ".[security]"   # installs pip-audit

cyberjection audit --deps --secrets --targets --config examples/quickstart.yaml
cyberjection audit --compliance --report audit-report.md
# exits 0 (clean) or 1 (a check found something); --targets never fails
# the gate on its own -- it's informational, see docs/SECURITY.md
```

List registered plugins and serve the dashboard API:

```bash
cyberjection plugins   # every registered mutator/strategy/evaluator/exporter alias

pip install -e ".[api]"   # installs uvicorn
cyberjection serve --host 127.0.0.1 --port 8000
```

Fast local check before committing (no cost, nothing leaves the machine):

```bash
cyberjection run --config cyberjection.yaml --target local-model --local-only
```

or as a pre-commit hook:

```yaml
repos:
  - repo: https://github.com/ShivamS-design/cyberjection
    rev: v0.12.0
    hooks:
      - id: cyberjection-hubguard
      - id: cyberjection-local
        args: [--config, cyberjection.yaml, --target, local-model]
```

In GitHub Actions:

```yaml
- uses: ShivamS-design/cyberjection@v0.12.0
  with:
    command: run
    config: cyberjection.yaml
    target: support-agent
```

OWASP Top 10 for LLM Applications coverage from a run's JSON:

```bash
cyberjection export --from-json results.json --format owasp-llm --output owasp.md
```

Audit a model repository's supply chain before deploying it (Phase 11):

```bash
cyberjection hubguard scan meta-llama/Llama-3-8B-Instruct --block-remote-code   --allow-org meta-llama --sarif-out hubguard.sarif   # gated repos need HF_TOKEN
cyberjection hubguard manifest meta-llama/Llama-3-8B-Instruct --out pins.yaml
cyberjection hubguard scan meta-llama/Llama-3-8B-Instruct --manifest pins.yaml --verify-downloads
cyberjection hubguard file ./downloads/pytorch_model.bin   # local files, never loaded
cyberjection hubguard gate -c examples/hubguard_campaign.yaml
# exits 0 (PASS/WARN), 4 (BLOCK), or 2 (usage error)
```

```python
import asyncio
from cyberjection.hubguard.client import HubGuardClient
from cyberjection.hubguard.safetensors import EnforcementLevel

async def main():
    scanner = HubGuardClient(
        repo_id="suspicious-org/custom-llama-3-weights",
        safetensors_policy=EnforcementLevel.STRICT,
        scan_remote_code=True,
        scan_pickles=True,
    )
    report = await scanner.audit_repository()
    print(f"Repository: {report.repo_id}")
    print(f"Safety Verdict: {report.verdict.value}")
    print(f"Risk Score: {report.risk_score}/10")
    for finding in report.findings:
        print(f"[{finding.severity.value.upper()}] {finding.category.value}: {finding.description}")

asyncio.run(main())
```

To serve the web dashboard too, build it once (`cd apps/dashboard && npm
install && npm run build`) and add `--dashboard-dir apps/dashboard/dist`
to `cyberjection serve`; the dashboard and the API then share one origin.
See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for details.

## Project layout

```
cyberjection/
├── cyberjection/
│   ├── cli/             # main.py (Typer app: run, inspect, export, audit, plugins, serve, hubguard)
│   ├── config/          # schema.py, loader.py
│   ├── providers/       # base.py, litellm_provider.py
│   ├── mutators/        # base.py, registry.py, base64_mutator.py, unicode_mutator.py,
│   │                    # typoglycemia.py, rot13.py
│   ├── attacks/         # base.py, registry.py, prompt_injection.py, jailbreak.py,
│   │                    # system_extraction.py, state.py, attacker.py, crescendo.py, tap.py
│   ├── evaluators/      # base.py, registry.py, ahocorasick.py, regex.py, llamaguard.py,
│   │                    # llmjudge.py, cascade.py, regexes/*.txt
│   ├── persistence/     # models.py, sqlite.py, repository.py, resumability.py
│   ├── reporting/       # models.py, registry.py, sarif.py, exporters.py, quality_gate.py
│   ├── distributed/     # celery_app.py, rate_limiter.py, coordinator.py, retry.py, tasks.py
│   ├── security/        # input_validation.py, audit_log.py, secrets_audit.py,
│   │                    # dependency_audit.py, compliance.py
│   ├── orchestrator/    # campaign.py
│   ├── plugins/         # base.py, loader.py, registry.py
│   ├── api/             # asgi.py, app.py, server.py, static.py
│   ├── hubguard/        # client.py, picklescan.py, remotecode.py, sandbox.py, safetensors.py,
│   │                    # secrets.py, weightscan.py, transport.py, models.py, gate.py
│   └── utils/           # exceptions.py, context.py
├── apps/
│   └── dashboard/       # Vite + React + TypeScript web dashboard
├── alembic/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/         # 0001_initial_schema.py
├── .github/workflows/
│   └── cyberjection.yml  # CI/CD security evaluation gate
├── .gitlab-ci.yml        # GitLab CI equivalent
├── examples/
│   ├── quickstart.yaml
│   └── hubguard_campaign.yaml
├── tests/
│   └── unit/
├── docs/
├── .env.example
├── alembic.ini
└── pyproject.toml
```

## Testing

```bash
pytest tests/unit/ -v
mypy cyberjection/config/ cyberjection/providers/ cyberjection/mutators/ cyberjection/attacks/ cyberjection/evaluators/ cyberjection/plugins/ cyberjection/api/ cyberjection/hubguard/
pytest tests/unit/ --cov=cyberjection --cov-report=term-missing
```

See [`docs/TESTING.md`](docs/TESTING.md) for what each test module covers
and the conventions used for mocking the provider layer.

## License

Apache License 2.0. See [LICENSE](LICENSE).
