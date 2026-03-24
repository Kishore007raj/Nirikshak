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
    seen_resources = set()

    for finding in findings:
        sev = normalize_severity(finding.get("severity"))
        base = SEVERITY_WEIGHTS.get(sev, 0)

        # Context: internet exposure boost
        if finding.get("exposed_to_internet"):
            base *= 2

        # Context: sensitive data boost
        if finding.get("sensitive_data"):
            base *= 2

        # Context: production asset boost
        if finding.get("environment") == "prod":
            base += 3

        # Basic deduplication by resource
        resource_id = finding.get("resource_id")
        if resource_id in seen_resources:
            continue
        seen_resources.add(resource_id)

        score += base

    # Cap score to avoid inflation
    return min(score, 100)


def summarize_severity(findings: List[Dict]) -> Dict[str, int]:
    """Count findings by severity."""

    summary: Dict[str, int] = {k: 0 for k in SEVERITY_WEIGHTS.keys()}

    for finding in findings:
        sev = normalize_severity(finding.get("severity"))

        # Context-aware bump
        if finding.get("exposed_to_internet") and sev != "CRITICAL":
            if sev == "HIGH":
                sev = "CRITICAL"
            elif sev == "MEDIUM":
                sev = "HIGH"

        summary[sev] = summary.get(sev, 0) + 1

    return summary