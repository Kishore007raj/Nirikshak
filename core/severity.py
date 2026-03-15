"""
Severity model.

Defines severity levels and risk scoring logic
for detected misconfigurations.
"""

from typing import Dict, List

SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}


def normalize_severity(severity: str) -> str:
    """Normalize severity labels to canonical values."""
    if not severity:
        return "LOW"

    key = str(severity).strip().upper()
    return key if key in SEVERITY_WEIGHTS else "LOW"


def calculate_risk_score(findings: List[Dict]) -> int:
    """Calculate a risk score from a list of findings."""

    score = 0
    for finding in findings:
        sev = normalize_severity(finding.get("severity"))
        score += SEVERITY_WEIGHTS.get(sev, 0)
    return score


def summarize_severity(findings: List[Dict]) -> Dict[str, int]:
    """Count findings by severity."""

    summary: Dict[str, int] = {k: 0 for k in SEVERITY_WEIGHTS.keys()}
    for finding in findings:
        sev = normalize_severity(finding.get("severity"))
        summary[sev] = summary.get(sev, 0) + 1
    return summary
