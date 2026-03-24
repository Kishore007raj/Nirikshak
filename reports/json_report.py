"""
Generates structured JSON reports containing
scan results, severity summaries, and findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from core.models import ScanResult


def generate_json_report(scan_result: ScanResult, output_path: str = "nirikshak_report.json") -> None:
    """Generate a JSON report from a scan result."""

    report: Dict[str, Any] = {
        "scan_id": scan_result.scan_id,
        "timestamp": scan_result.timestamp,
        "summary": {
            "critical": scan_result.severity_count.get("CRITICAL", 0),
            "high": scan_result.severity_count.get("HIGH", 0),
            "medium": scan_result.severity_count.get("MEDIUM", 0),
            "low": scan_result.severity_count.get("LOW", 0),
        },
        "risk_score": scan_result.risk_score,
        "findings": [
            {
                "resource_id": f.resource_id,
                "type": f.resource_type,
                "severity": f.severity,
                "description": f.description,
                "impact": f.impact,
                "fix_suggestion": f.fix_suggestion
            }
            for f in scan_result.findings
        ],
    }

    output_file = Path(output_path)
    output_file.write_text(json.dumps(report, indent=4))

    print(f"JSON report generated: {output_file}")
