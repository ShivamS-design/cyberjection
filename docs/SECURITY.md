# Security policy

This document covers two things: how to report a vulnerability in
Cyberjection itself, and how to use the hardening tooling this project
ships (Phase 8) to audit your own deployment and campaign configuration.

## Reporting a vulnerability

If you find a security issue in Cyberjection -- not a finding your
campaign surfaced against a *target* model, but an issue in this
project's own code -- please report it privately rather than opening a
public GitHub issue, so a fix can ship before the details are public.

1. Open a [GitHub Security Advisory](https://github.com/ShivamS-design/cyberjection/security/advisories/new)
   on this repository (preferred), or contact a maintainer directly
   through GitHub if advisories aren't available to you.
2. Include a description of the issue, the affected version/commit, and
   reproduction steps if you have them. A minimal proof-of-concept is
   more useful than a general description.
3. Please allow a reasonable window to investigate and prepare a fix
   before any public disclosure.

This project has no bug-bounty program and cannot offer monetary
rewards, but every credible report is investigated and credited in the
fix's changelog entry unless you ask not to be.

## What "security" means for this project

Cyberjection is a red-teaming tool: its entire purpose is generating
adversarial input against *other* systems. That creates two distinct
security surfaces worth separating clearly:

- **The target's security** -- whether a model under test resists
  jailbreaks, prompt injection, or data exfiltration. This is what the
  Tier 1-3 evaluation cascade (`cyberjection/evaluators/`) measures, and
  it is the normal, intended output of running a campaign. A finding
  here is a result, not a vulnerability in Cyberjection.
- **Cyberjection's own security** -- whether the tool itself is safe to
  run against your own infrastructure and credentials: does a malformed
  campaign config escape its working directory, can a target's response
  exhaust memory, are your API keys ever logged or leaked, is a
  dependency this project relies on carrying a known CVE. This is what
  Phase 8's `cyberjection/security/` package and the `audit` CLI command
  exist to help you check.

## Hardening controls shipped in Phase 8

All controls below are implemented in `cyberjection/security/` and wired
into the CLI in `cyberjection/cli/main.py`. See
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md#phase-8-security-auditing-compliance--production-hardening)
for implementation detail and [`docs/COMPLIANCE.md`](COMPLIANCE.md) for
the full control-by-control self-assessment.

### Output-path containment

Every CLI flag that writes a report (`--sarif-out`, `--json-out`,
`--markdown-out`, `-o`/`--output`, `--report`) is passed through
`assert_safe_output_path` before anything is written. A *relative* path
that resolves outside the current working directory -- via a `..`
segment or a symlink planted inside an otherwise-trusted output
directory -- is rejected with a usage error (exit code `2`) rather than
silently writing outside the intended location. An explicit *absolute*
path is treated as your deliberate choice (e.g. writing to a CI
artifacts mount) and is not subject to this check.

### Target URL SSRF guard

`assert_safe_target_url` is a literal-value check applied to
`TargetConfig.api_base`: it rejects unsupported URL schemes, a small set
of always-blocked hostnames (`localhost`, `metadata.google.internal`),
and literal IP addresses that are private, loopback, link-local,
reserved, or multicast. It does **not** perform DNS resolution -- see
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md#ssrf-guard-is-a-literal-value-check-not-a-dns-resolving-one)
for why. Legitimate local-network targets (a self-hosted Ollama or vLLM
deployment) need `allow_private_networks=True` to pass; the `cyberjection
audit --targets` CLI check surfaces a flagged target as an informational
finding only, since a private target URL is a normal and expected
configuration, not a defect by itself.

### Payload size ceiling

`enforce_payload_size_limit` bounds an individual prompt or response
payload to 1 MB by default (`DEFAULT_MAX_PAYLOAD_BYTES`), measured in
UTF-8 encoded bytes (not character count, so multi-byte mutator output
like zero-width/homoglyph payloads is sized correctly). Guards against
unbounded memory growth or database bloat from a pathological or
adversarial target response.

### Hash-chained audit log

Every `run`, `inspect`, `export`, and `audit` invocation writes a
structured entry to a local, append-only audit log
(`.cyberjection/audit.jsonl` by default; override with the
`CYBERJECTION_AUDIT_LOG` environment variable). Each entry carries a
SHA-256 hash of its own content plus the previous entry's hash, forming
a tamper-*evident* chain: `cyberjection.security.audit_log.verify_chain()`
detects modification of any existing entry. This does not prevent an
attacker with filesystem write access from truncating the log and
starting a fresh chain -- there is no append-only filesystem enforcement
or remote log shipping in this phase.

### Dependency vulnerability scanning

```bash
pip install -e ".[security]"   # installs pip-audit
cyberjection audit --deps
```

Shells out to the real `pip-audit` tool against the live PyPA Advisory
Database. If `pip-audit` isn't installed, the report says so honestly
(`source="unavailable"`) rather than reporting a false "clean" result.
Pass `--fail-on-unavailable` (used by this project's own CI
`hardening-gate` job) to make a missing `pip-audit` install a hard
failure instead of a silent pass.

### Hardcoded-secret scanning

```bash
cyberjection audit --secrets --path . --config your-campaign.yaml
```

Scans a source tree for patterns that look like committed credentials
(AWS access keys and secret keys, PEM private key headers, Slack tokens,
GitHub tokens, and a generic `api_key`/`secret_key`/`access_token`
assignment pattern), and separately checks a campaign YAML file's
`api_key` fields for a literal value instead of a `${VAR}` environment
interpolation. Every reported excerpt is redacted -- the raw matched
secret is never printed or logged.

### Compliance self-assessment

```bash
cyberjection audit --compliance
cyberjection audit --compliance --report audit-report.md
```

Prints (or writes as Markdown) a control-by-control self-assessment
against OWASP ASVS 4.0 and the SOC 2 (2017) Trust Services Criteria. See
[`docs/COMPLIANCE.md`](COMPLIANCE.md) for the full table and an
explanation of why this is a self-assessment, not a certification.

## Known limitations

- The SSRF guard is literal-value only; it does not resolve or pin DNS,
  so a hostname that resolves to a private address at connection time
  (rather than at config-validation time) is not caught. See the ASVS-V9.1
  entry in `docs/COMPLIANCE.md`.
- The audit log's hash chain is tamper-*evident*, not tamper-*proof*: an
  attacker with filesystem write access to the log file can truncate it
  and start a new chain undetected by `verify_chain()` alone.
- The dependency audit depends on the live PyPA Advisory Database via
  `pip-audit`; it reflects data available at the moment it runs, not a
  point-in-time guarantee, and requires the optional `security` extra
  (and, in most environments, network access) to run at all.
- The secret scanner is pattern-based and will miss secrets that don't
  match a known shape (e.g. an arbitrary internal token format), and can
  false-positive on high-entropy strings that happen to match a generic
  pattern. It is a defense-in-depth check, not a substitute for a
  dedicated secret-scanning service or pre-commit hook in front of your
  own fork's CI.
- None of this phase's controls apply to a target's own infrastructure --
  they protect *this tool's* operation, not the system under test.
