import json
from datetime import datetime


def generate_json_report(findings, severity_count, scan_id, scan_time, risk_score):

    report = {
        "scan_id": scan_id,
        "scan_timestamp": scan_time,
        "risk_score": risk_score,
        "summary": severity_count,
        "total_findings": len(findings),
        "findings": findings
    }

    with open("nirikshak_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("JSON report generated: nirikshak_report.json")
