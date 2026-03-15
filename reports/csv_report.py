"""CSV reporting for scan findings."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List

from core.models import Finding


def generate_csv_report(findings: List[Finding], output_path: str = "nirikshak_report.csv") -> None:
    """Generate a CSV report for the findings."""

    output_file = Path(output_path)
    with output_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "rule_id",
            "severity",
            "resource_id",
            "provider",
            "cis_reference",
            "timestamp",
        ])

        for finding in findings:
            writer.writerow([
                finding.rule_id,
                finding.severity,
                finding.resource_id,
                finding.provider,
                finding.cis_reference,
                finding.timestamp,
            ])

    print(f"CSV report generated: {output_file}")
