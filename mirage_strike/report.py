"""Report generation: Markdown + SARIF v2.1.0."""

from __future__ import annotations

import datetime
import json
from typing import List

from .client import ExploitResult

_SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def to_markdown(results: List[ExploitResult], target: str, mode: str) -> str:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    vuln = [r for r in results if r.success]
    blocked = [r for r in results if not r.success]
    lines = [
        "# mirage-strike report",
        "",
        f"- **Target:** `{target}`",
        f"- **Mode:** {mode}",
        f"- **Generated:** {ts}",
        f"- **Modules run:** {len(results)}",
        f"- **Exploited (vulnerable):** {len(vuln)}",
        f"- **Blocked:** {len(blocked)}",
        "",
        "## Summary",
        "",
        "| OWASP ID | Vulnerability | Severity | Result |",
        "|---|---|---|---|",
    ]
    for r in results:
        status = "VULNERABLE" if r.success else "blocked"
        lines.append(
            f"| {r.vuln_id} | {r.name} | {r.severity} | {status} |"
        )
    lines.append("")
    lines.append("## Details")
    lines.append("")
    for r in results:
        lines.append(f"### {r.vuln_id} -- {r.name}")
        lines.append("")
        lines.append(f"- Severity: **{r.severity}**")
        lines.append(f"- Result: **{'VULNERABLE' if r.success else 'blocked'}**")
        lines.append(f"- Detail: {r.detail}")
        if r.success and r.evidence:
            ev = r.evidence.replace("`", "'")[:400]
            lines.append(f"- Evidence:\n\n```\n{ev}\n```")
        if not r.success and r.blocked_reason:
            lines.append(f"- Blocked because: {r.blocked_reason}")
        lines.append("")
    return "\n".join(lines)


def to_sarif(results: List[ExploitResult], target: str) -> dict:
    rules = []
    sarif_results = []
    seen_rules = set()
    for r in results:
        if r.vuln_id not in seen_rules:
            seen_rules.add(r.vuln_id)
            rules.append(
                {
                    "id": r.vuln_id,
                    "name": r.name.replace(" ", ""),
                    "shortDescription": {"text": r.name},
                    "fullDescription": {"text": r.detail},
                    "defaultConfiguration": {
                        "level": _SEVERITY_TO_SARIF.get(r.severity, "warning")
                    },
                    "properties": {"security-severity": _sev_score(r.severity)},
                }
            )
        if r.success:  # only emit a finding for an actual exploited vuln
            sarif_results.append(
                {
                    "ruleId": r.vuln_id,
                    "level": _SEVERITY_TO_SARIF.get(r.severity, "warning"),
                    "message": {
                        "text": f"{r.name}: exploit succeeded. {r.detail}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target or "mirage"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "properties": {"evidence": r.evidence[:300]},
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mirage-strike",
                        "informationUri": "https://github.com/VISHNU0906/mirage",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _sev_score(sev: str) -> str:
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.0",
        "low": "3.0",
        "info": "0.0",
    }.get(sev, "5.0")


def write_reports(results, target, mode, md_path, sarif_path):
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(results, target, mode))
    with open(sarif_path, "w", encoding="utf-8") as fh:
        json.dump(to_sarif(results, target), fh, indent=2)
