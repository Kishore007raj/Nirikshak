"""
Exports scan findings into CSV format
for compliance audits and external analysis.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List

from core.models import ScanResult

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
            "provider",
            "cis_reference",
            "fix_suggestion",
            "description",
            "impact"
        ])

        for finding in scan_result.findings:
            writer.writerow([
                scan_result.scan_id,
                scan_result.timestamp,
                scan_result.risk_score,
                finding.rule_id,
                finding.severity,
                finding.resource_id,
                finding.provider,
                finding.cis_reference,
                finding.fix_suggestion,
                finding.description,
                finding.impact
            ])

    print(f"CSV report generated: {output_file}")
