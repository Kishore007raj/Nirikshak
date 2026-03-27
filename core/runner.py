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
from utils.time import get_ist_time
import time
import logging


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

    logger = logging.getLogger(__name__)

    scan_id = str(uuid.uuid4())
    timestamp = get_ist_time()
    start_time = time.time()

    logger.debug("Loading rules")
    rules = load_rules()

    logger.debug("Running engine on %s resources", len(resources))
    findings = run_engine(resources, rules)

    severity_count = summarize_severity(findings)
    risk_score = calculate_risk_score(findings)
    
    end_time = time.time()
    scan_time_sec = end_time - start_time
    
    # KPIs
    res_count = len(resources)
    issues_count = len(findings)
    resources_per_sec = res_count / scan_time_sec if scan_time_sec > 0 else 0.0
    findings_density = issues_count / res_count if res_count > 0 else 0.0

    metrics = {
        "scan_time_sec": round(scan_time_sec, 2),
        "resources": res_count,
        "issues": issues_count,
        "resources_per_sec": round(resources_per_sec, 1),
        "findings_density": round(findings_density, 2)
    }

    # Compliance Tracking
    total_frameworks = set()
    total_controls = set()
    for r in rules:
        for c in r.get("compliance", []):
            total_frameworks.add(c.get("framework"))
            total_controls.add(c.get("control_id"))
            
    failed_controls = set()
    for f in findings:
        for c in f.get("compliance", []):
            failed_controls.add(c.get("control_id"))
            
    passed_count = len(total_controls) - len(failed_controls)
    score = round((passed_count / len(total_controls)) * 100, 1) if total_controls else 100.0
    
    compliance = {
        "frameworks": list(total_frameworks),
        "score": score,
        "failed_controls": list(failed_controls)
    }

    logger.debug(
        "Scan complete: %s findings (risk score=%s)",
        len(findings),
        risk_score,
    )

    scan_result = ScanResult(
        scan_id=scan_id,
        provider=provider,
        mode=mode,
        timestamp=timestamp,
        resources=resources,
        findings=[Finding(**f) for f in findings],
        severity_count=severity_count,
        risk_score=risk_score,
        metrics=metrics,
        compliance=compliance
    )

    return scan_result
