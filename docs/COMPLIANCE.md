# Compliance self-assessment

**This is a self-assessment, not a certification.** A SOC 2 report can
only be issued by a licensed, independent CPA firm after an actual audit
of an organization's operating controls over a review period; nothing on
this page claims Cyberjection *is* SOC 2 compliant, or that it has passed
an ASVS certification (ASVS itself is a verification standard, not a
certifying body). What this page provides is a structured, code-linked
map of which technical controls a security-minded reviewer would look
for are implemented, partially implemented, not applicable, or not yet
implemented -- the kind of internal control inventory that is a normal
*input* to a real audit, not a substitute for one.

Every row's Evidence column points at a real module, function, or test in
this repository -- not a policy document or a claim without a code
anchor. A control with no honest evidence to point at is marked
`NOT_IMPLEMENTED` or `PARTIAL` rather than `IMPLEMENTED`; the point of
this registry is to be a checklist a maintainer (or a prospective user
doing their own diligence) can actually act on, which requires it not
overclaim.

## How this page is generated

This table is rendered directly from `CONTROL_REGISTRY` in
[`cyberjection/security/compliance.py`](../cyberjection/security/compliance.py)
via `generate_compliance_report()`. To regenerate it after editing the
registry:

```bash
cyberjection audit --compliance --report docs/COMPLIANCE.md
```

(then trim the command's own console-log lines from the top of the file,
leaving just the Markdown report body below).

## Summary

| Status | Count |
|---|---|
| IMPLEMENTED | 9 |
| PARTIAL | 6 |
| NOT_APPLICABLE | 3 |
| NOT_IMPLEMENTED | 0 |

## OWASP ASVS 4.0

| Control | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| ASVS-V1.1 | A verified architecture and threat model exists and is kept current | IMPLEMENTED | `docs/ARCHITECTURE.md#threat-model-summary` | Threat model table maps concrete risks to concrete mitigations, updated every phase. |
| ASVS-V2 | Authentication controls | NOT_APPLICABLE | - | Cyberjection is a locally-run CLI/library with no network-facing authentication surface as of Phase 8. Revisit once Phase 10's web dashboard/API introduces one. |
| ASVS-V4 | Access control | NOT_APPLICABLE | - | Single-operator CLI tool; no multi-user authorization boundary exists yet. |
| ASVS-V5.1 | Input validation is applied to all untrusted input | IMPLEMENTED | `cyberjection/security/input_validation.py:assert_safe_output_path`<br>`cyberjection/security/input_validation.py:assert_safe_target_url`<br>`cyberjection/security/input_validation.py:enforce_payload_size_limit`<br>`cyberjection/config/schema.py (Pydantic field validation)` | - |
| ASVS-V5.2 | Sanitization / safe deserialization of structured input | IMPLEMENTED | `cyberjection/config/loader.py:_parse_yaml (uses yaml.safe_load, never yaml.load)` | - |
| ASVS-V7.1 | Security-relevant events are logged with enough detail for later review | IMPLEMENTED | `cyberjection/security/audit_log.py:AuditLogger`<br>`cyberjection/cli/main.py (audit_logger.log(...) call sites)` | - |
| ASVS-V7.4 | Log records are protected against unauthorized modification | PARTIAL | `cyberjection/security/audit_log.py:verify_chain` | Hash-chained log entries make tampering with an existing entry detectable via verify_chain(), but the log file itself has no filesystem-level write protection or off-host replication -- an attacker with delete access can still truncate and restart the chain. Full protection needs an append-only or remote log sink, which is deployment-environment-specific and out of this library's scope. |
| ASVS-V9.1 | TLS is used for all external service communication | PARTIAL | `cyberjection/providers/litellm_provider.py (delegates HTTPS handling to litellm/httpx)` | Relies on litellm's own default HTTPS behavior; not independently verified or pinned by this codebase. |
| ASVS-V12.1 | Path traversal is prevented on file operations driven by external input | IMPLEMENTED | `cyberjection/security/input_validation.py:assert_safe_output_path`<br>`tests/unit/test_input_validation.py` | - |
| ASVS-V13 | API and web service security controls | NOT_APPLICABLE | - | No REST API exists yet as of Phase 8; revisit when Phase 10 ships one. |
| ASVS-V14.2 | Dependencies are tracked and checked against known vulnerabilities | IMPLEMENTED | `cyberjection/security/dependency_audit.py:run_dependency_audit`<br>`.github/workflows/cyberjection.yml` | - |
| ASVS-V14.3 | No secrets are hardcoded in source or configuration | IMPLEMENTED | `cyberjection/security/secrets_audit.py`<br>`cyberjection/config/loader.py (${VAR} expansion keeps secrets out of YAML)`<br>`cyberjection/config/schema.py (api_key: SecretStr, never reprinted)` | - |

## SOC 2 (2017 Trust Services Criteria)

| Control | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| SOC2-CC6.1 | Logical access to systems and data is restricted to authorized users | PARTIAL | `cyberjection/config/schema.py (SecretStr credential handling)` | Credential handling exists; no multi-user access control model exists yet (single-operator tool). |
| SOC2-CC6.6 | Vulnerabilities in the software supply chain are identified and addressed | IMPLEMENTED | `cyberjection/security/dependency_audit.py`<br>`.github/workflows/cyberjection.yml` | - |
| SOC2-CC6.8 | Unauthorized or malicious changes to software are prevented or detected | PARTIAL | `cyberjection/security/secrets_audit.py`<br>`.github/workflows/cyberjection.yml (CI runs on every push/PR)` | Secret and dependency scanning run in CI; there is no code-signing or branch-protection enforcement configurable from within this repository's own tooling. |
| SOC2-CC7.2 | Security events are monitored and anomalies are identified | PARTIAL | `cyberjection/security/audit_log.py` | Events are captured in a tamper-evident log; no automated alerting/anomaly-detection layer consumes it yet. |
| SOC2-CC7.3 | Identified security events are evaluated and responded to | PARTIAL | `cyberjection/security/audit_log.py:verify_chain`<br>`docs/SECURITY.md (vulnerability disclosure process)` | A disclosure/response process is documented; response is currently a manual maintainer action, not an automated workflow. |
| SOC2-CC8.1 | Changes to infrastructure, data, and software are authorized, tested, and approved before deployment | IMPLEMENTED | `.github/workflows/cyberjection.yml`<br>`.gitlab-ci.yml`<br>`tests/unit/ (full suite gates every change)` | - |

## Reading the PARTIAL entries

Six controls are marked `PARTIAL` rather than `IMPLEMENTED`. Each one has
real, working evidence behind it -- the gap is between what this project
can enforce as a library/CLI and what requires deployment-environment
configuration this codebase can't control from inside itself:

- **ASVS-V7.4 / SOC2-CC7.2 / SOC2-CC7.3** (audit log protection and
  monitoring): the hash chain makes tampering *detectable*, not
  *impossible* -- true immutability needs an append-only filesystem or a
  remote log sink outside this project's scope, and there's no automated
  alerting consuming the log yet.
- **ASVS-V9.1** (TLS): correctly delegated to `litellm`/`httpx`'s own
  defaults rather than reimplemented, but not independently pinned or
  verified by this codebase.
- **SOC2-CC6.1** (access control): credential handling (`SecretStr`) is
  solid, but there's no multi-user authorization model, because
  Cyberjection is a single-operator CLI tool as of Phase 8.
- **SOC2-CC6.8** (change control): CI-enforced secret/dependency scanning
  exists, but branch protection and code signing are GitHub/GitLab
  repository settings, not something this codebase configures for you.

None of these are silently assumed away -- see the `notes` field on each
`ControlMapping` in `cyberjection/security/compliance.py` for the full
reasoning, and [`docs/SECURITY.md`](SECURITY.md#known-limitations) for
the corresponding known-limitations list.
