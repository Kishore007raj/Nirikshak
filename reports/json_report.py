import json
from datetime import datetime


def generate_json_report(findings, severity_count):

    report = {
        "scan_timestamp": datetime.utcnow().isoformat(),
        "summary": severity_count,
        "total_findings": len(findings),
        "findings": findings
    }

    with open("nirikshak_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("JSON report generated: nirikshak_report.json")
