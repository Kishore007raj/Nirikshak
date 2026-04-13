"""
FastAPI application for Nirikshak.

Provides REST API endpoints to:
- start scans (POST /scan/{provider})
- retrieve latest scan results (GET /results)
- fetch scan history (GET /history)
- download PDF reports (GET /download/{scan_id})
- stream real-time scans (WebSocket /ws/scan)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from cloud.scanner import collect_resources
from core.runner import run_scan
from database.sqlite import init_db, save_scan, get_scans
from utils.helpers import load_demo_data
from reports.pdf_report import generate_pdf_report
from terraform.plan_parser import parse_terraform_plan
from utils.time import get_ist_time

logger = logging.getLogger(__name__)

app = FastAPI(title="Nirikshak CSPM", version="0.1.0")

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    init_db()
    # Ensure necessary directories exist
    Path(os.getenv("OUTPUT_PATH", "output")).mkdir(parents=True, exist_ok=True)
    Path("terraform").mkdir(parents=True, exist_ok=True)


@app.get("/api/health")
def root():
    return {
        "status": "healthy",
        "message": "NIRIKSHAK API running",
        "timestamp": get_ist_time()
    }


# ── Scan ─────────────────────────────────────────────────────────────────────
@app.post("/scan/{provider}")
def create_scan(provider: str):
    provider = provider.lower().strip()

    if provider not in {"aws", "azure", "gcp", "terraform"}:
        raise HTTPException(status_code=400, detail="invalid provider")

    mode = "real" if provider == "azure" else "demo"

    try:
        if provider == "terraform":
            # Terraform fallback check
            plan_path = "terraform/plan.json"
            if not Path(plan_path).exists():
                Path("terraform").mkdir(exist_ok=True)
                Path(plan_path).write_text('{"planned_values": {"root_module": {"resources": []}}}')
            resources = parse_terraform_plan(plan_path)
            mode = "iac"
        else:
            resources = collect_resources(provider, mode)
    except Exception as e:
        if provider == "azure":
            raise HTTPException(status_code=500, detail=str(e))
        logger.warning("Live collect failed for %s: %s — falling back to demo data", provider, e)
        resources = []

    # For aws/gcp: fall back to demo data when live collect returned nothing
    if not resources and provider in {"aws", "gcp"}:
        try:
            resources = load_demo_data(provider)
        except Exception as e:
            logger.warning("Demo data load failed for %s: %s", provider, e)

    try:
        scan_result = run_scan(provider, mode, resources)
        save_scan(scan_result)
        pdf_path = generate_pdf_report(scan_result)
    except Exception as e:
        logger.error("Scan pipeline failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

    # findings are strictly normalized by engine, just convert to dict
    normalized_findings = [f.__dict__ for f in scan_result.findings]

    sc = scan_result.severity_count or {}
    return {
        "scan_id": scan_result.scan_id,
        "provider": provider,
        "status": "completed",
        "risk_score": scan_result.risk_score,
        "summary": {
            "critical": sc.get("CRITICAL", 0),
            "high":     sc.get("HIGH", 0),
            "medium":   sc.get("MEDIUM", 0),
            "low":      sc.get("LOW", 0),
        },
        "findings": normalized_findings,
        "compliance": scan_result.compliance,
        "metrics": scan_result.metrics,
        "timestamp": scan_result.timestamp,
        "report_path": f"/download/{scan_result.scan_id}"
    }


# ── PDF Download ─────────────────────────────────────────────────────────────
@app.get("/download/{scan_id}")
def download_report(scan_id: str):
    output_dir = Path(os.getenv("OUTPUT_PATH", "output"))
    pdf_path = output_dir / f"report_{scan_id}.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"nirikshak_report_{scan_id}.pdf",
        headers={
            "Content-Disposition": f'attachment; filename="nirikshak_report_{scan_id}.pdf"'
        }
    )

# Keep legacy endpoint for backward compat
@app.get("/report/{scan_id}")
def report_redirect(scan_id: str):
    return download_report(scan_id)


# ── Results ───────────────────────────────────────────────────────────────────
_EMPTY_RESULT: Dict[str, Any] = {
    "risk_score": 0,
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "findings": [],
    "compliance": {},
    "metrics": {},
    "timestamp": "",
}


@app.get("/results")
def get_latest_result():
    try:
        scans = get_scans()
    except Exception as e:
        logger.error("DB error in /results: %s", e)
        return _EMPTY_RESULT

    if not scans:
        return _EMPTY_RESULT

    latest = scans[0]
    findings = latest.get("findings") or []

    normalized_findings = [f if isinstance(f, dict) else f.__dict__ for f in findings]

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in normalized_findings:
        sev = str(f.get("severity", "")).upper()
        if sev == "CRITICAL":
            summary["critical"] += 1
        elif sev == "HIGH":
            summary["high"] += 1
        elif sev == "MEDIUM":
            summary["medium"] += 1
        elif sev == "LOW":
            summary["low"] += 1

    return {
        "risk_score": latest.get("risk_score", 0),
        "summary":    summary,
        "findings":   normalized_findings,
        "compliance": latest.get("compliance", {}),
        "metrics":    latest.get("metrics", {}),
        "timestamp":  latest.get("timestamp", ""),
        "report_path": f"/download/{latest.get('scan_id')}"
    }


# ── History ───────────────────────────────────────────────────────────────────
@app.get("/history")
def get_history():
    try:
        return get_scans()
    except Exception as e:
        logger.error("DB error in /history: %s", e)
        return []

# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/scan")
async def websocket_scan(ws: WebSocket):
    await ws.accept()

    while True:
        try:
            data = await ws.receive_json()
            provider = data.get("provider")
            
            if not provider:
                continue

            provider = provider.lower().strip()
            await ws.send_json({"status": "started"})

            try:
                mode = "real" if provider == "azure" else "demo"
    
                # Pipeline Stage 1: collect_resources
                await ws.send_json({"status": "progress", "stage": "collect_resources", "progress": 15})
                if provider == "terraform":
                    plan_path = "terraform/plan.json"
                    if not Path(plan_path).exists():
                        Path("terraform").mkdir(exist_ok=True)
                        Path(plan_path).write_text('{"planned_values": {"root_module": {"resources": []}}}')
                    resources = parse_terraform_plan(plan_path)
                    mode = "iac"
                else:
                    resources = collect_resources(provider, mode)
    
                if not resources and provider in {"aws", "gcp"}:
                    resources = load_demo_data(provider)
                
                # Pipeline Stage 2: normalize
                await ws.send_json({"status": "progress", "stage": "normalize", "progress": 30})
    
                # Pipeline Stage 3: run_scan
                await ws.send_json({"status": "progress", "stage": "run_scan", "progress": 50})
                scan_result = run_scan(provider, mode, resources)
                
                # Pipeline Stage 4: severity/scoring
                await ws.send_json({"status": "progress", "stage": "severity", "progress": 70})
    
                # Pipeline Stage 5: reports
                await ws.send_json({"status": "progress", "stage": "reports", "progress": 85})
                generate_pdf_report(scan_result)
                
                # Pipeline Stage 6: save_scan
                await ws.send_json({"status": "progress", "stage": "save_scan", "progress": 95})
                save_scan(scan_result)

                # findings are strictly normalized by engine, just serialize
                normalized_findings = [f.__dict__ for f in (scan_result.findings or [])]
    
                await ws.send_json({
                    "status": "completed",
                    "data": {
                        "scan_id": scan_result.scan_id,
                        "provider": provider,
                        "timestamp": scan_result.timestamp,
                        "risk_score": scan_result.risk_score,
                        "summary": scan_result.severity_count,
                        "findings": normalized_findings,
                        "compliance": scan_result.compliance,
                        "metrics": scan_result.metrics,
                        "report_path": f"/download/{scan_result.scan_id}"
                    }
                })
    
            except Exception as e:
                logger.error("WebSocket scan pipeline failed: %s", str(e))
                await ws.send_json({
                    "status": "error",
                    "message": str(e)
                })
        except Exception:
            break

# Mount frontend dashboard at the root level (ensure this is after all API routes)
app.mount("/", StaticFiles(directory="dashboard", html=True), name="dashboard")

