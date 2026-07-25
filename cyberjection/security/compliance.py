"""Control-readiness self-assessment mapped to OWASP ASVS 4.0 and the
SOC 2 (2017) Trust Services Criteria.

**This is a self-assessment, not a certification.** A SOC 2 report can
only be issued by a licensed, independent CPA firm after an actual audit
of an organization's operating controls over a review period; nothing in
this module or `docs/COMPLIANCE.md` claims Cyberjection *is* SOC 2
compliant. What this provides is a structured, code-linked map of which
technical controls a security-minded reviewer would look for are
implemented, partially implemented, not applicable, or not yet
implemented -- the kind of internal control inventory that's a normal
*input* to a real audit, not a substitute for one.

Every `ControlMapping.evidence` entry points at a real module, function,
or test in this repository. A control with no honest evidence to point
at is marked `NOT_IMPLEMENTED` or `PARTIAL` rather than `IMPLEMENTED` --
the point of this registry is to be a trustworthy checklist a maintainer
can act on, which requires it not overclaim.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple

ASVS = "OWASP ASVS 4.0"
SOC2 = "SOC 2 (2017 Trust Services Criteria)"


class ControlStatus(str, Enum):
    IMPLEMENTED = "IMPLEMENTED"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


@dataclass(frozen=True)
class ControlMapping:
    control_id: str
    framework: str
    title: str
    status: ControlStatus
    evidence: Tuple[str, ...]
    notes: str = ""


CONTROL_REGISTRY: List[ControlMapping] = [
    # -- OWASP ASVS 4.0 -----------------------------------------------
    ControlMapping(
        control_id="ASVS-V1.1",
        framework=ASVS,
        title="A verified architecture and threat model exists and is kept current",
        status=ControlStatus.IMPLEMENTED,
        evidence=("docs/ARCHITECTURE.md#threat-model-summary",),
        notes="Threat model table maps concrete risks to concrete mitigations, updated every phase.",
    ),
    ControlMapping(
        control_id="ASVS-V2",
        framework=ASVS,
        title="Authentication controls",
        status=ControlStatus.PARTIAL,
        evidence=("cyberjection/api/", "docker-compose.yml", "docs/DEPLOYMENT.md"),
        notes=(
            "Phase 10's dashboard API (cyberjection.api) introduced Cyberjection's first "
            "network-facing surface, and it deliberately implements no authentication of its "
            "own -- the 'single trusted team, one instance' deployment model documented in "
            "docs/DEPLOYMENT.md puts the operator's own network perimeter/reverse proxy in "
            "front of it instead of building a second, likely-worse auth layer inside this "
            "project. Every endpoint is also read-only (see docs/ARCHITECTURE.md's Phase 10 "
            "section), so the surface an unauthenticated caller can reach is bounded to "
            "already-completed campaign history, not campaign execution."
        ),
    ),
    ControlMapping(
        control_id="ASVS-V4",
        framework=ASVS,
        title="Access control",
        status=ControlStatus.NOT_APPLICABLE,
        evidence=(),
        notes=(
            "Still no multi-user authorization boundary: the CLI remains single-operator, "
            "and Phase 10's dashboard API has no user/session concept to scope access "
            "within -- see ASVS-V2's note above for why that's a deployment-perimeter "
            "decision rather than an in-app access-control gap."
        ),
    ),
    ControlMapping(
        control_id="ASVS-V5.1",
        framework=ASVS,
        title="Input validation is applied to all untrusted input",
        status=ControlStatus.IMPLEMENTED,
        evidence=(
            "cyberjection/security/input_validation.py:assert_safe_output_path",
            "cyberjection/security/input_validation.py:assert_safe_target_url",
            "cyberjection/security/input_validation.py:enforce_payload_size_limit",
            "cyberjection/config/schema.py (Pydantic field validation)",
        ),
    ),
    ControlMapping(
        control_id="ASVS-V5.2",
        framework=ASVS,
        title="Sanitization / safe deserialization of structured input",
        status=ControlStatus.IMPLEMENTED,
        evidence=("cyberjection/config/loader.py:_parse_yaml (uses yaml.safe_load, never yaml.load)",),
    ),
    ControlMapping(
        control_id="ASVS-V7.1",
        framework=ASVS,
        title="Security-relevant events are logged with enough detail for later review",
        status=ControlStatus.IMPLEMENTED,
        evidence=("cyberjection/security/audit_log.py:AuditLogger", "cyberjection/cli/main.py (audit_logger.log(...) call sites)"),
    ),
    ControlMapping(
        control_id="ASVS-V7.4",
        framework=ASVS,
        title="Log records are protected against unauthorized modification",
        status=ControlStatus.PARTIAL,
        evidence=("cyberjection/security/audit_log.py:verify_chain",),
        notes=(
            "Hash-chained log entries make tampering with an existing entry "
            "detectable via verify_chain(), but the log file itself has no "
            "filesystem-level write protection or off-host replication -- an "
            "attacker with delete access can still truncate and restart the "
            "chain. Full protection needs an append-only or remote log sink, "
            "which is deployment-environment-specific and out of this "
            "library's scope."
        ),
    ),
    ControlMapping(
        control_id="ASVS-V9.1",
        framework=ASVS,
        title="TLS is used for all external service communication",
        status=ControlStatus.PARTIAL,
        evidence=("cyberjection/providers/litellm_provider.py (delegates HTTPS handling to litellm/httpx)",),
        notes="Relies on litellm's own default HTTPS behavior; not independently verified or pinned by this codebase.",
    ),
    ControlMapping(
        control_id="ASVS-V12.1",
        framework=ASVS,
        title="Path traversal is prevented on file operations driven by external input",
        status=ControlStatus.IMPLEMENTED,
        evidence=("cyberjection/security/input_validation.py:assert_safe_output_path", "tests/unit/test_input_validation.py"),
    ),
    ControlMapping(
        control_id="ASVS-V13",
        framework=ASVS,
        title="API and web service security controls",
        status=ControlStatus.PARTIAL,
        evidence=(
            "cyberjection/api/asgi.py",
            "cyberjection/api/app.py",
            "tests/unit/test_api.py",
            "tests/unit/test_api_persistence.py",
        ),
        notes=(
            "The REST API Phase 10 ships is intentionally minimal and read-only (5 GET "
            "endpoints, no mutation, no request body parsing -- see "
            "cyberjection/api/asgi.py's module docstring), which removes several ASVS-V13 "
            "subcontrols by construction (no injection surface via a request body, no "
            "state-changing endpoint to authorize). It does not implement authentication, "
            "rate limiting, or CORS policy -- those are left to the deployment's own reverse "
            "proxy per docs/DEPLOYMENT.md, not implemented in-app."
        ),
    ),
    ControlMapping(
        control_id="ASVS-V14.2",
        framework=ASVS,
        title="Dependencies are tracked and checked against known vulnerabilities",
        status=ControlStatus.IMPLEMENTED,
        evidence=("cyberjection/security/dependency_audit.py:run_dependency_audit", ".github/workflows/cyberjection.yml"),
    ),
    ControlMapping(
        control_id="ASVS-V14.3",
        framework=ASVS,
        title="No secrets are hardcoded in source or configuration",
        status=ControlStatus.IMPLEMENTED,
        evidence=(
            "cyberjection/security/secrets_audit.py",
            "cyberjection/config/loader.py (${VAR} expansion keeps secrets out of YAML)",
            "cyberjection/config/schema.py (api_key: SecretStr, never reprinted)",
        ),
    ),
    # -- SOC 2 (2017 Trust Services Criteria) --------------------------
    ControlMapping(
        control_id="SOC2-CC6.1",
        framework=SOC2,
        title="Logical access to systems and data is restricted to authorized users",
        status=ControlStatus.PARTIAL,
        evidence=("cyberjection/config/schema.py (SecretStr credential handling)",),
        notes="Credential handling exists; no multi-user access control model exists yet (single-operator tool).",
    ),
    ControlMapping(
        control_id="SOC2-CC6.6",
        framework=SOC2,
        title="Vulnerabilities in the software supply chain are identified and addressed",
        status=ControlStatus.IMPLEMENTED,
        evidence=("cyberjection/security/dependency_audit.py", ".github/workflows/cyberjection.yml"),
    ),
    ControlMapping(
        control_id="SOC2-CC6.8",
        framework=SOC2,
        title="Unauthorized or malicious changes to software are prevented or detected",
        status=ControlStatus.PARTIAL,
        evidence=("cyberjection/security/secrets_audit.py", ".github/workflows/cyberjection.yml (CI runs on every push/PR)"),
        notes="Secret and dependency scanning run in CI; there is no code-signing or branch-protection enforcement configurable from within this repository's own tooling.",
    ),
    ControlMapping(
        control_id="SOC2-CC7.2",
        framework=SOC2,
        title="Security events are monitored and anomalies are identified",
        status=ControlStatus.PARTIAL,
        evidence=("cyberjection/security/audit_log.py",),
        notes="Events are captured in a tamper-evident log; no automated alerting/anomaly-detection layer consumes it yet.",
    ),
    ControlMapping(
        control_id="SOC2-CC7.3",
        framework=SOC2,
        title="Identified security events are evaluated and responded to",
        status=ControlStatus.PARTIAL,
        evidence=("cyberjection/security/audit_log.py:verify_chain", "docs/SECURITY.md (vulnerability disclosure process)"),
        notes="A disclosure/response process is documented; response is currently a manual maintainer action, not an automated workflow.",
    ),
    ControlMapping(
        control_id="SOC2-CC8.1",
        framework=SOC2,
        title="Changes to infrastructure, data, and software are authorized, tested, and approved before deployment",
        status=ControlStatus.IMPLEMENTED,
        evidence=(".github/workflows/cyberjection.yml", ".gitlab-ci.yml", "tests/unit/ (full suite gates every change)"),
    ),
]


def generate_compliance_report(registry: List[ControlMapping] = CONTROL_REGISTRY) -> str:
    """Renders `registry` as a Markdown document grouped by framework,
    one table per framework, in the order frameworks first appear in the
    registry. This is what `docs/COMPLIANCE.md` is generated from -- see
    that file's own header for how to regenerate it."""

    lines: List[str] = []
    frameworks: List[str] = []
    for mapping in registry:
        if mapping.framework not in frameworks:
            frameworks.append(mapping.framework)

    for framework in frameworks:
        lines.append(f"## {framework}\n")
        lines.append("| Control | Title | Status | Evidence | Notes |")
        lines.append("|---|---|---|---|---|")
        for mapping in registry:
            if mapping.framework != framework:
                continue
            evidence = "<br>".join(f"`{e}`" for e in mapping.evidence) or "-"
            notes = mapping.notes.replace("\n", " ") or "-"
            lines.append(f"| {mapping.control_id} | {mapping.title} | {mapping.status.value} | {evidence} | {notes} |")
        lines.append("")

    return "\n".join(lines)


def compliance_summary(registry: List[ControlMapping] = CONTROL_REGISTRY) -> Dict[str, int]:
    """Counts controls by status, e.g. `{"IMPLEMENTED": 9, "PARTIAL": 6,
    "NOT_APPLICABLE": 3, "NOT_IMPLEMENTED": 0}`."""

    summary: Dict[str, int] = {status.value: 0 for status in ControlStatus}
    for mapping in registry:
        summary[mapping.status.value] += 1
    return summary
