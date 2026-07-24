"""Security auditing, compliance mapping, and production-hardening utilities.

Phase 8 does not add a new attack/evaluation capability -- it hardens and
audits everything the first seven phases already built:

- `input_validation`: guards against path traversal on report output paths,
  unintentional SSRF-shaped target URLs, and unbounded payload sizes.
- `audit_log`: structured, hash-chained (tamper-evident) audit logging for
  security-relevant events -- CLI invocations, campaign lifecycle,
  quality-gate outcomes.
- `secrets_audit`: scans repository files and campaign YAML for
  accidentally-committed credentials, distinct from Tier 1's
  `RegexEvaluator` (which scans *target responses* for leaked secrets, not
  the codebase's own files).
- `dependency_audit`: checks declared dependencies against known
  vulnerability advisories via the real `pip-audit` tool when it's
  installed, and honestly reports `source="unavailable"` -- never a
  fabricated or stale offline advisory list -- when it isn't.
- `compliance`: a structured control registry mapping specific code and
  tests in this repository to OWASP ASVS and SOC 2 Trust Services
  Criteria control IDs, and a Markdown report generator.

None of this is a substitute for a real third-party security audit or a
certified SOC 2 attestation -- `compliance.py`'s own module docstring and
`docs/COMPLIANCE.md` are explicit that this is a self-assessment, not a
certification.
"""
