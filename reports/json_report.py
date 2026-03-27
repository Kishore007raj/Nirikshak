"""
Generates structured JSON reports containing
scan results, severity summaries, and findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

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


def generate_json_report(scan_result: ScanResult, output_path: str = "nirikshak_report.json") -> None:
    """Generate a JSON report from a scan result."""

    report: Dict[str, Any] = {
        "scan_id": scan_result.scan_id,
        "timestamp": scan_result.timestamp,
        "provider": scan_result.provider,
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
                "description": f.description if f.description else generate_description(f.resource_type, f.severity),
                "impact": f.impact if f.impact else generate_impact(f.resource_type, f.severity),
                "fix_suggestion": f.fix_suggestion if f.fix_suggestion else generate_fix(f.resource_type, f.severity),
                "compliance": _format_compliance(f.compliance),
            }
            for f in scan_result.findings
        ],
        "compliance": scan_result.compliance,
        "metrics": scan_result.metrics,
    }

    output_file = Path(output_path)
    output_file.write_text(json.dumps(report, indent=4))
