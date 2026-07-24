"""SARIF 2.1.0 exporter.

Maps `Finding`s onto the OASIS Static Analysis Results Interchange Format
(SARIF) v2.1.0 JSON schema, for direct ingestion into GitHub Advanced
Security's code scanning alerts, GitLab's Security Dashboard, and
enterprise SIEMs that speak SARIF.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from cyberjection.reporting.models import Finding

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


class SARIFReporter:
    """Generates standardized SARIF v2.1.0 reports for enterprise security
    pipeline consumption.

    Two bugs in the Phase 6 design spec's own `SARIFReporter.export`
    sketch are fixed here:

    1. The spec hardcoded the error/warning severity split at a fixed
       score of 7.0, independent of whatever `--threshold` the caller
       actually configured for the run. A finding scoring 5.0 under a
       `--threshold 4.0` run has already failed that run's quality gate,
       but the spec's SARIF output would still label it "note"/"warning"
       -- understating severity relative to the very gate that failed it.
       `export()` now takes the effective `threshold` and derives SARIF
       `level` from it, so severity in the exported report always agrees
       with the quality gate decision for the same run.
    2. The spec appended one `rules` entry per finding with no
       deduplication, so a rule that fired on more than one test case
       (a realistic, common case -- e.g. the same `CJ-001` rule
       triggering on several seed prompts in one campaign) would appear
       multiple times in `tool.driver.rules`, each under a different
       `ruleIndex`, with `results[].ruleIndex` pointing at whichever
       occurrence happened to be built last. SARIF's `rules` array is
       meant to be a one-entry-per-rule-id catalog referenced *by*
       `ruleIndex`, not a per-result log. `export()` now builds `rules`
       keyed by `rule_id`, deduplicated, with each result's `ruleIndex`
       pointing at that rule's single catalog entry.
    """

    @staticmethod
    def export(findings: List[Finding], output_path: Path, *, threshold: float = 7.0) -> None:
        rule_index_by_id: Dict[str, int] = {}
        rules: List[dict] = []
        sarif_results: List[dict] = []

        for finding in findings:
            if finding.rule_id not in rule_index_by_id:
                rule_index_by_id[finding.rule_id] = len(rules)
                rules.append(
                    {
                        "id": finding.rule_id,
                        "shortDescription": {"text": f"Evaluation rule {finding.rule_id}"},
                        "fullDescription": {
                            "text": f"Policy evaluation for category: {finding.category}"
                        },
                        "defaultConfiguration": {
                            "level": "error" if finding.score >= threshold else "warning"
                        },
                    }
                )

            sarif_results.append(
                {
                    "ruleId": finding.rule_id,
                    "ruleIndex": rule_index_by_id[finding.rule_id],
                    "level": "error" if finding.score >= threshold else "note",
                    "message": {"text": f"Security score {finding.score:.1f} - {finding.details}"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": finding.location}}}
                    ],
                }
            )

        sarif_payload = {
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Cyberjection", "version": "1.0.0", "rules": rules}},
                    "results": sarif_results,
                }
            ],
        }

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(sarif_payload, handle, indent=2)
            handle.write("\n")
