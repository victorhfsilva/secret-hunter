"""Reporting helpers: JSON dump and a readable text/markdown summary."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def build_report(candidates: list[dict], analyses: dict[str, dict],
                 targets: list[str], pages: int, errors: list[str],
                 provider: str | None, subdomains: dict[str, list[str]] | None = None,
                 mask: bool = False) -> dict[str, Any]:
    findings = []
    for cand in candidates:
        key = f"{cand['type']}::{cand['value']}"
        analysis = analyses.get(key)
        finding = {**cand, "analysis": analysis}
        if mask:
            # Privacy mode: only the masked value is retained in the report.
            finding["value"] = cand.get("masked", cand["value"])
            finding["masked"] = cand.get("masked", cand["value"])
        else:
            # Plain text: expose the full value and drop the masked field.
            finding.pop("masked", None)
        findings.append(finding)
    # Sort: reportable first, then by score.
    def sort_key(f):
        a = f.get("analysis") or {}
        crit = a.get("criticality", "Informational")
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                 "Informational": 4, "FalsePositive": 5}
        return (order.get(crit, 5), -(a.get("score", 0.0) or 0.0))
    findings.sort(key=sort_key)
    return {
        "tool": "secret-hunter",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "provider": provider,
        "pages_fetched": pages,
        "candidates_found": len(candidates),
        "subdomains_discovered": {
            apex: subs for apex, subs in (subdomains or {}).items()
        },
        "errors": errors,
        "findings": findings,
    }


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)


def render_text(report: dict) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append(" SECRET-HUNTER REPORT")
    lines.append("=" * 78)
    lines.append(f" Targets        : {', '.join(report['targets'])}")
    lines.append(f" LLM provider   : {report['provider'] or '(none - regex only)'}")
    lines.append(f" Pages fetched  : {report['pages_fetched']}")
    lines.append(f" Candidates     : {report['candidates_found']}")
    subs = report.get("subdomains_discovered") or {}
    if subs:
        total = sum(len(v) for v in subs.values())
        lines.append(f" Subdomains     : {total} across {len(subs)} domain(s)")
    if report["errors"]:
        lines.append(f" Errors         : {len(report['errors'])}")
    lines.append("")
    lines.append(f" {'CRITICALITY':<16}{'SCORE':<7}{'TYPE':<26}{'VALUE':<40}")
    lines.append("-" * 78)
    for f in report["findings"]:
        a = f.get("analysis") or {}
        crit = a.get("criticality", "Informational")
        score = f"{a.get('score', 0.0):.1f}"
        value = f.get("value", "")
        lines.append(f" {crit:<16}{score:<7}{f['type']:<26}{value:<40}")
        if a.get("explanation"):
            lines.append(f"   -> {a['explanation']}")
        if a.get("impact"):
            lines.append(f"   impact: {a['impact']}")
        if a.get("remediation"):
            lines.append(f"   fix: {a['remediation']}")
        lines.append(f"   source: {f['source']} (line {f.get('line', '?')})")
        lines.append("")
    return "\n".join(lines)
