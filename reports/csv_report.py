"""
Exports scan findings into CSV format
for compliance audits and external analysis.
"""

from __future__ import annotations

import csv
from pathlib import Path

from core.models import ScanResult
from utils.fallback import generate_description, generate_impact, generate_fix


def _format_compliance(compliance) -> str:
    """Format compliance list into a readable string."""
    if not compliance:
        return "CIS Benchmark"
    if isinstance(compliance, str):
        return compliance
    parts = []
    for entry in compliance:
        if isinstance(entry, dict):
            fw = entry.get("framework", "")
            ctrl = entry.get("control_id", "")
            if fw and ctrl:
                parts.append(f"{fw} {ctrl}")
            elif ctrl:
                parts.append(ctrl)
        elif isinstance(entry, str):
            parts.append(entry)
    return ", ".join(parts) if parts else "CIS Benchmark"


def generate_csv_report(scan_result: ScanResult, output_path: str = "nirikshak_report.csv") -> None:
    """Generate a CSV report for the findings."""

    output_file = Path(output_path)
    with output_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scan_id",
            "timestamp",
            "risk_score",
            "rule_id",
            "severity",
            "resource_id",
            "resource_type",
            "provider",
            "description",
            "impact",
            "fix_suggestion",
            "compliance",
        ])

        for finding in scan_result.findings:
            res_type = finding.resource_type or "unknown"
            sev = finding.severity or "MEDIUM"

            writer.writerow([
                scan_result.scan_id,
                scan_result.timestamp,
                scan_result.risk_score,
                finding.rule_id,
                sev,
                finding.resource_id,
                res_type,
                finding.provider,
                finding.description if finding.description else generate_description(res_type, sev),
                finding.impact if finding.impact else generate_impact(res_type, sev),
                finding.fix_suggestion if finding.fix_suggestion else generate_fix(res_type, sev),
                _format_compliance(finding.compliance),
            ])
