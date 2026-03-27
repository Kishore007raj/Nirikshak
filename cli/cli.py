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
from utils.logger import setup_logging

app = typer.Typer(help="Nirikshak - Cloud Security Misconfiguration Scanner")


def _print_summary(scan_result, quiet: bool = False, output_json: str = "", output_csv: str = ""):
    """Print the scan summary to the console."""
    if quiet:
        print(f"Total findings: {len(scan_result.findings)}")
        print(f"Risk Score: {scan_result.risk_score}")
        print(f"Report file path: {output_json}")
        return

    print(f"Scan ID: {scan_result.scan_id}")
    print(f"Provider: {scan_result.provider}")
    print(f"Mode: {scan_result.mode}")
    print(f"Resources scanned: {len(scan_result.resources)}")

    print("\n=== FINDINGS ===\n")
    
    if not scan_result.findings:
        print("No misconfigurations found\n")
    else:
        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(scan_result.findings, key=lambda f: severity_order.get(f.severity, 99))
        
        for f in sorted_findings:
            print(f"[{f.severity}] {f.title}")
            print(f"Resource: {f.resource_id}")
            if f.impact: 
                print(f"Impact: {f.impact}")
            if f.fix_suggestion: 
                print(f"Fix: {f.fix_suggestion}")
            print("")

    print("Summary:")
    print(f"Critical: {scan_result.severity_count.get('CRITICAL', 0)}")
    print(f"High: {scan_result.severity_count.get('HIGH', 0)}")
    print(f"Medium: {scan_result.severity_count.get('MEDIUM', 0)}")
    print(f"Low: {scan_result.severity_count.get('LOW', 0)}")
    
    print(f"\nRisk Score: {scan_result.risk_score}")

    print("\nReports:")
    print(f"* {output_json}")
    print(f"* {output_csv}\n")


def _run_scan(
    provider: str,
    mode: str,
    region: Optional[str],
    profile: Optional[str],
    output_json: str,
    output_csv: str,
    quiet: bool,
    verbose: bool,
):
    """Run a full scan and emit reports."""
    setup_logging(verbose=verbose, quiet=quiet)

    if provider == "terraform":
        from terraform.plan_parser import parse_terraform_plan
        from pathlib import Path
        plan_path = "terraform/plan.json"
        mode = "iac"
        if not Path(plan_path).exists():
            Path("terraform").mkdir(exist_ok=True)
            Path(plan_path).write_text('{"planned_values": {"root_module": {"resources": []}}}')
        resources = parse_terraform_plan(plan_path)
    else:
        resources = collect_resources(provider, mode, region=region, profile=profile)
        
    scan_result = run_scan(provider, mode, resources)
    init_db()
    save_scan_result(scan_result)

    generate_json_report(scan_result, output_json)
    generate_csv_report(scan_result, output_csv)

    _print_summary(scan_result, quiet=quiet, output_json=output_json, output_csv=output_csv)


@app.command()
def scan(
    provider: str = typer.Argument(..., help="Cloud provider name (aws, azure, gcp)"),
    region: Optional[str] = typer.Option(None, help="Region to scan (if supported)."),
    profile: Optional[str] = typer.Option(None, help="Cloud provider profile to use."),
    output_json: str = typer.Option("nirikshak_report.json", help="Output JSON report path."),
    output_csv: str = typer.Option("nirikshak_report.csv", help="Output CSV report path."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Show only essential summary."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
):
    """Run a live scan against a cloud provider (requires credentials)."""

    mode = "real" if provider.lower() == "azure" else "demo"
    _run_scan(
        provider=provider,
        mode=mode,
        region=region,
        profile=profile,
        output_json=output_json,
        output_csv=output_csv,
        quiet=quiet,
        verbose=verbose,
    )


@app.command()
def demo(
    provider: str = typer.Argument(..., help="Cloud provider name (aws, azure, gcp)"),
    region: Optional[str] = typer.Option(None, help="Region to use for demo resources."),
    output_json: str = typer.Option("nirikshak_report.json", help="Output JSON report path."),
    output_csv: str = typer.Option("nirikshak_report.csv", help="Output CSV report path."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Show only essential summary."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
):
    """Run a demo scan using local fixture data."""

    _run_scan(
        provider=provider,
        mode="demo",
        region=region,
        profile=None,
        output_json=output_json,
        output_csv=output_csv,
        quiet=quiet,
        verbose=verbose,
    )


if __name__ == "__main__":
    app()
