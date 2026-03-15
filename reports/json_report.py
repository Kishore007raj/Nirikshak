"""Report generation utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from core.models import ScanResult


def generate_json_report(scan_result: ScanResult, output_path: str = "nirikshak_report.json") -> None:
    """Generate a JSON report from a scan result."""

    report: Dict[str, Any] = {
        "scan_id": scan_result.scan_id,
        "scan_timestamp": scan_result.timestamp,
        "provider": scan_result.provider,
        "mode": scan_result.mode,
        "risk_score": scan_result.risk_score,
        "summary": scan_result.severity_count,
        "total_findings": len(scan_result.findings),
        "findings": [f.__dict__ for f in scan_result.findings],
    }

    output_file = Path(output_path)
    output_file.write_text(json.dumps(report, indent=4))

    print(f"JSON report generated: {output_file}")
