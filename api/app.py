"""
FastAPI application for Nirikshak.

Provides REST API endpoints to:
- start scans
- retrieve scan results
- fetch findings
- expose reports to the dashboard
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional

from cloud.scanner import collect_resources
from core.runner import run_scan
from database.sqlite import init_db, save_scan_result, get_scan, list_findings

app = FastAPI(title="Nirikshak CSPM", version="0.1.0")


class ScanRequest(BaseModel):
    provider: str = Field(..., description="Cloud provider (aws|azure|gcp)")
    mode: str = Field("demo", description="Scan mode: 'demo' or 'real'")
    region: Optional[str] = Field(None, description="Cloud region (where applicable)")
    profile: Optional[str] = Field(None, description="Cloud SDK profile to use")


@app.on_event("startup")
def startup_event():
    init_db()


@app.post("/scan")
def create_scan(request: ScanRequest):
    """Start a new scan and persist the results."""

    resources = collect_resources(
        request.provider, request.mode, region=request.region, profile=request.profile
    )
    scan_result = run_scan(request.provider, request.mode, resources)

    save_scan_result(scan_result)

    return {"scan_id": scan_result.scan_id, "status": "completed"}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan.scan_id,
        "provider": scan.provider,
        "mode": scan.mode,
        "timestamp": scan.timestamp,
        "risk_score": scan.risk_score,
        "severity_count": scan.severity_count,
        "findings": [f.__dict__ for f in scan.findings],
    }


@app.get("/findings")
def get_findings():
    findings = list_findings()
    return [f.__dict__ for f in findings]
