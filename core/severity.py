"""
Severity model.

Defines severity levels and risk scoring logic
for detected misconfigurations.
"""

from __future__ import annotations
from typing import Dict, List, Any

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


def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    """Calculate a risk score from a list of findings.

    Incorporates context boosts for internet exposure and sensitive data.
    """

    score = 0
    seen_resources = set()

    for finding in findings:
        sev = normalize_severity(finding.get("severity", ""))
        base = SEVERITY_WEIGHTS.get(sev, 0)

        # Context: internet exposure boost (2x)
        if finding.get("exposed_to_internet"):
            base *= 2

        # Context: sensitive data boost (1.5x for storage/databases)
        if finding.get("sensitive_data"):
            base = int(base * 1.5)

        # Basic deduplication by resource to avoid skewed scores on single resources
        resource_id = finding.get("resource_id")
        if resource_id and resource_id in seen_resources:
            # Add a smaller penalty for secondary findings on same resource
            score += max(1, base // 4)
            continue
            
        if resource_id:
            seen_resources.add(resource_id)

        score += base

    # Cap score at 100 for dashboard presentation
    return min(score, 100)


def summarize_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by severity, with context-aware severity bumping."""

    summary: Dict[str, int] = {k: 0 for k in SEVERITY_WEIGHTS.keys()}

    for finding in findings:
        sev = normalize_severity(finding.get("severity", ""))

        # Context-aware bump: If high/medium is exposed to internet, bump it
        if finding.get("exposed_to_internet") and sev != "CRITICAL":
            if sev == "HIGH":
                sev = "CRITICAL"
            elif sev == "MEDIUM":
                sev = "HIGH"

        summary[sev] = summary.get(sev, 0) + 1

    return summary