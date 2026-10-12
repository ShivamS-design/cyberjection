"""OWASP Top 10 for LLM Applications (2025) coverage report.

Maps every finding onto the 2025 list and renders a Markdown matrix: for
each category, how many tests exercised it, how many breached the
threshold, the worst score, and a status of FAIL, PASS or NOT TESTED.
NOT TESTED is reported explicitly, so a clean report can't be mistaken
for full coverage.

Findings are mapped by their category (`owasp_category` on a test case,
else the strategy name), accepting both 2025 and 2023 identifiers and
plain keywords, since the 2023 list numbered several risks differently
(e.g. sensitive information disclosure was LLM06 and is now LLM02).

Registered as the `owasp-llm` exporter:
`cyberjection run ... --markdown-out` stays the plain summary;
`cyberjection export --from-json results.json --format owasp-llm -o owasp.md`
produces this report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cyberjection.reporting.models import Finding
from cyberjection.reporting.registry import register_exporter

OWASP_LLM_2025: List[Tuple[str, str]] = [
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM03", "Supply Chain"),
    ("LLM04", "Data and Model Poisoning"),
    ("LLM05", "Improper Output Handling"),
    ("LLM06", "Excessive Agency"),
    ("LLM07", "System Prompt Leakage"),
    ("LLM08", "Vector and Embedding Weaknesses"),
    ("LLM09", "Misinformation"),
    ("LLM10", "Unbounded Consumption"),
]

# Keyword -> 2025 id, checked in order (more specific first).
_KEYWORDS: List[Tuple[str, str]] = [
    ("system_prompt", "LLM07"),
    ("prompt_leak", "LLM07"),
    ("sensitive_info", "LLM02"),
    ("information_disclosure", "LLM02"),
    ("pii", "LLM02"),
    ("supply_chain", "LLM03"),
    ("hubguard", "LLM03"),
    ("poison", "LLM04"),
    ("backdoor", "LLM04"),
    ("weights", "LLM04"),
    ("output_handling", "LLM05"),
    ("insecure_output", "LLM05"),
    ("excessive_agency", "LLM06"),
    ("agency", "LLM06"),
    ("vector", "LLM08"),
    ("embedding", "LLM08"),
    ("rag", "LLM08"),
    ("misinformation", "LLM09"),
    ("overreliance", "LLM09"),
    ("hallucination", "LLM09"),
    ("unbounded", "LLM10"),
    ("consumption", "LLM10"),
    ("denial_of_service", "LLM10"),
    ("budget_exceeded", "LLM10"),
    ("prompt_injection", "LLM01"),
    ("jailbreak", "LLM01"),
    ("crescendo", "LLM01"),
    ("tap", "LLM01"),
]

# 2023 ids whose meaning moved in 2025 (only used when no keyword matched).
_LEGACY_2023 = {"LLM02": "LLM05", "LLM03": "LLM04", "LLM04": "LLM10", "LLM05": "LLM03", "LLM06": "LLM02", "LLM08": "LLM06", "LLM09": "LLM09"}
_ID_RE = re.compile(r"\bLLM(0[1-9]|10)\b", re.IGNORECASE)
_NOT_A_RESULT = {"configuration_error", "skipped_local_only"}


def map_category(category: str) -> Optional[str]:
    """2025 OWASP LLM id for a finding category, or None if unmapped."""

    text = category.lower().replace("-", "_").replace("/", "_").replace(" ", "_")
    for keyword, owasp_id in _KEYWORDS:
        if keyword in text:
            return owasp_id
    match = _ID_RE.search(category)
    if match:
        found = f"LLM{match.group(1)}"
        is_2025 = ":2025" in category or "2025" in category
        return found if is_2025 else _LEGACY_2023.get(found, found)
    return None


@dataclass
class CategoryResult:
    owasp_id: str
    name: str
    tests: int = 0
    failing: int = 0
    max_score: float = 0.0
    rules: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.tests == 0:
            return "NOT TESTED"
        return "FAIL" if self.failing else "PASS"


def build_matrix(findings: List[Finding], threshold: float) -> Tuple[Dict[str, CategoryResult], List[Finding]]:
    matrix = {oid: CategoryResult(oid, name) for oid, name in OWASP_LLM_2025}
    unmapped: List[Finding] = []
    for finding in findings:
        if finding.category in _NOT_A_RESULT:
            continue
        owasp_id = map_category(finding.category) or map_category(finding.rule_id)
        if owasp_id is None:
            unmapped.append(finding)
            continue
        row = matrix[owasp_id]
        row.tests += 1
        row.max_score = max(row.max_score, finding.score)
        if finding.score >= threshold:
            row.failing += 1
            row.rules.append(finding.rule_id)
    return matrix, unmapped


@register_exporter("owasp-llm")
class OWASPLLMReporter:
    @staticmethod
    def export(findings: List[Finding], output_path: Path, *, threshold: float = 7.0) -> None:
        matrix, unmapped = build_matrix(findings, threshold)
        tested = sum(1 for row in matrix.values() if row.tests)
        failing = [row for row in matrix.values() if row.status == "FAIL"]
        lines = [
            "# OWASP Top 10 for LLM Applications (2025) Coverage",
            "",
            f"**Result:** {'FAIL' if failing else 'PASS'} -- {len(failing)} of {tested} tested categories "
            f"have findings at or above the {threshold:.1f} threshold; {10 - tested} of 10 categories were not tested.",
            "",
            "| ID | Category | Tests | Failing | Max score | Status |",
            "|---|---|---|---|---|---|",
        ]
        for row in matrix.values():
            lines.append(f"| {row.owasp_id} | {row.name} | {row.tests} | {row.failing} | {row.max_score:.1f} | {row.status} |")
        if failing:
            lines += ["", "## Failing tests", ""]
            for row in failing:
                lines.append(f"- **{row.owasp_id} {row.name}:** " + ", ".join(f"`{r}`" for r in row.rules))
        if unmapped:
            lines += ["", "## Findings not mapped to an OWASP category", ""]
            lines += [f"- `{f.rule_id}` ({f.category}), score {f.score:.1f}" for f in unmapped]
        lines += [
            "",
            "_NOT TESTED means no test in this campaign targeted the category. Coverage, not a "
            "certification: map additional tests with `owasp_category` in the campaign YAML._",
            "",
        ]
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
