"""
Scan runner.

Coordinates the entire scanning pipeline:
collection -> normalization -> rule evaluation -> reporting.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from .engine import run_engine
from .loader import load_rules
from .severity import calculate_risk_score, summarize_severity
from .models import Finding, Resource, ScanResult


def run_scan(
    provider: str,
    mode: str,
    resources: List[Resource],
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> ScanResult:
    """Run a scan given a list of normalized resources.

    This function is intentionally generic: callers are responsible for collecting
    resources (from cloud APIs, demo data, or IaC plans) and passing them in.
    """

    scan_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()

    rules = load_rules()
    findings = run_engine(resources, rules)

    severity_count = summarize_severity(findings)
    risk_score = calculate_risk_score(findings)

    scan_result = ScanResult(
        scan_id=scan_id,
        provider=provider,
        mode=mode,
        timestamp=timestamp,
        resources=resources,
        findings=[Finding(**f) for f in findings],
        severity_count=severity_count,
        risk_score=risk_score,
    )

    return scan_result
