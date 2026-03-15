"""
CLI entrypoint for Nirikshak.

Handles user commands such as:
- scan aws
- scan azure
- scan gcp

Initializes scan lifecycle, loads configuration,
and triggers the cloud scanning pipeline.
"""

from __future__ import annotations

import logging
from typing import Optional

import typer

from cloud.scanner import collect_resources
from core.runner import run_scan
from database.sqlite import init_db, save_scan_result
from reports.csv_report import generate_csv_report
from reports.json_report import generate_json_report

app = typer.Typer(help="Nirikshak - Cloud Security Misconfiguration Scanner")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def _print_summary(scan_result):
    logging.info("Scan completed")
    logging.info("Scan ID: %s", scan_result.scan_id)
    logging.info("Provider: %s", scan_result.provider)
    logging.info("Mode: %s", scan_result.mode)
    logging.info("Timestamp: %s", scan_result.timestamp)

    for severity, count in scan_result.severity_count.items():
        logging.info("%s: %s", severity, count)

    logging.info("Risk score: %s", scan_result.risk_score)


def _run_scan(
    provider: str,
    mode: str,
    region: Optional[str],
    profile: Optional[str],
    output_json: str,
    output_csv: str,
):
    """Run a full scan and emit reports."""

    resources = collect_resources(provider, mode, region=region, profile=profile)
    scan_result = run_scan(provider, mode, resources)

    init_db()
    save_scan_result(scan_result)

    generate_json_report(scan_result, output_json)
    generate_csv_report(scan_result.findings, output_csv)

    _print_summary(scan_result)


@app.command()
def scan(
    provider: str = typer.Argument(..., help="Cloud provider name (aws, azure, gcp)"),
    region: Optional[str] = typer.Option(None, help="Region to scan (if supported)."),
    profile: Optional[str] = typer.Option(None, help="Cloud provider profile to use."),
    output_json: str = typer.Option("nirikshak_report.json", help="Output JSON report path."),
    output_csv: str = typer.Option("nirikshak_report.csv", help="Output CSV report path."),
):
    """Run a live scan against a cloud provider (requires credentials)."""

    _run_scan(
        provider=provider,
        mode="real",
        region=region,
        profile=profile,
        output_json=output_json,
        output_csv=output_csv,
    )


@app.command()
def demo(
    provider: str = typer.Argument(..., help="Cloud provider name (aws, azure, gcp)"),
    region: Optional[str] = typer.Option(None, help="Region to use for demo resources."),
    output_json: str = typer.Option("nirikshak_report.json", help="Output JSON report path."),
    output_csv: str = typer.Option("nirikshak_report.csv", help="Output CSV report path."),
):
    """Run a demo scan using local fixture data."""

    _run_scan(
        provider=provider,
        mode="demo",
        region=region,
        profile=None,
        output_json=output_json,
        output_csv=output_csv,
    )


if __name__ == "__main__":
    app()
