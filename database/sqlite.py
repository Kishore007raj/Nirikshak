"""SQLite-backed persistence for scan results."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import Finding, ScanResult


DEFAULT_DB_PATH = "nirikshak.db"


def _get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize the SQLite database schema."""

    conn = _get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            mode TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            findings JSON NOT NULL
        )"""
    )
    
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN compliance JSON")
    except sqlite3.OperationalError:
        pass
        
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN metrics JSON")
    except sqlite3.OperationalError:
        pass

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            cis_reference TEXT,
            timestamp TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        )"""
    )

    conn.commit()
    conn.close()


def save_scan(scan_result: ScanResult, db_path: str = DEFAULT_DB_PATH) -> None:
    """Persist a scan result to the database."""
    save_scan_result(scan_result, db_path)

def save_scan_result(scan_result: ScanResult, db_path: str = DEFAULT_DB_PATH) -> None:
    """Persist a scan result and its findings to the database."""

    conn = _get_connection(db_path)
    cursor = conn.cursor()

    import dataclasses

    findings_json = []
    for f in scan_result.findings:
        findings_json.append({
            "resource_id": f.resource_id,
            "type": f.resource_type,
            "severity": f.severity,
            "description": f.description,
            "impact": f.impact,
            "fix_suggestion": f.fix_suggestion,
            "compliance": f.compliance
        })

    cursor.execute(
        "INSERT OR REPLACE INTO scans (scan_id, provider, mode, timestamp, risk_score, findings, compliance, metrics) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_result.scan_id,
            scan_result.provider,
            scan_result.mode,
            scan_result.timestamp,
            scan_result.risk_score,
            json.dumps(findings_json),
            json.dumps(scan_result.compliance),
            json.dumps(scan_result.metrics)
        ),
    )

    cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_result.scan_id,))

    for finding in scan_result.findings:
        cursor.execute(
            """INSERT INTO findings
            (scan_id, rule_id, severity, resource_id, provider, cis_reference, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_result.scan_id,
                finding.rule_id,
                finding.severity,
                finding.resource_id,
                finding.provider,
                finding.cis_reference,
                finding.timestamp,
                finding.details,
            ),
        )

    conn.commit()
    conn.close()


def get_scan(scan_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[ScanResult]:
    """Retrieve a scan result by scan_id."""

    conn = _get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,))
    findings_rows = cursor.fetchall()

    findings: List[Finding] = []
    for fr in findings_rows:
        findings.append(
            Finding(
                rule_id=fr["rule_id"],
                title="",
                severity=fr["severity"],
                provider=fr["provider"],
                resource_id=fr["resource_id"],
                resource_type="",
                region="",
                cis_reference=fr["cis_reference"],
                timestamp=fr["timestamp"],
                details=fr["details"],
                compliance=[]
            )
        )
        
    row_keys = row.keys()

    scan = ScanResult(
        scan_id=row["scan_id"],
        provider=row["provider"],
        mode=row["mode"],
        timestamp=row["timestamp"],
        resources=[],
        findings=findings,
        severity_count={}, # Fallback since we dropped summary column
        risk_score=row["risk_score"],
        compliance=json.loads(row["compliance"] or "{}") if "compliance" in row_keys else {},
        metrics=json.loads(row["metrics"] or "{}") if "metrics" in row_keys else {}
    )

    conn.close()
    return scan


def get_scans(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve all scans."""
    conn = _get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    
    scans = []
    for row in rows:
        row_keys = row.keys()
        scans.append({
            "scan_id": row["scan_id"],
            "provider": row["provider"],
            "timestamp": row["timestamp"],
            "risk_score": row["risk_score"],
            "findings": json.loads(row["findings"] or "[]"),
            "compliance": json.loads(row["compliance"] or "{}") if "compliance" in row_keys and row["compliance"] else {},
            "metrics": json.loads(row["metrics"] or "{}") if "metrics" in row_keys and row["metrics"] else {}
        })
    conn.close()
    return scans


def list_findings(db_path: str = DEFAULT_DB_PATH) -> List[Finding]:
    """Return all findings across all scans."""

    conn = _get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM findings ORDER BY timestamp DESC")
    rows = cursor.fetchall()

    findings: List[Finding] = []
    for row in rows:
        findings.append(
            Finding(
                rule_id=row["rule_id"],
                title="",
                severity=row["severity"],
                provider=row["provider"],
                resource_id=row["resource_id"],
                resource_type="",
                region="",
                cis_reference=row["cis_reference"],
                timestamp=row["timestamp"],
                details=row["details"],
            )
        )

    conn.close()
    return findings
