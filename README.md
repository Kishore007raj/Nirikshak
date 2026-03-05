# Nirikshak

Nirikshak is an indigenous, self-hosted, rule-driven cloud misconfiguration security scanner designed to audit and validate cloud configurations across AWS, Azure, and GCP environments. It focuses on early detection of high-impact security misconfigurations aligned with CIS and NIST benchmarks, prioritizing transparency, auditability, and local deployment for academic, government, PSU, and SME environments.


## Overview

Nirikshak serves as a CSPM-lite reference framework for detecting cloud misconfigurations in controlled deployments. It emphasizes human-readable rules, self-hosted operation, and standards compliance without relying on foreign SaaS platforms.

## Problem Statement

Cloud misconfigurations pose significant risks to Indian government platforms, PSUs, BFSI, healthcare systems, and startups adopting cloud infrastructure. Common issues include public storage access, overly permissive network rules, disabled logging, and lack of encryption, leading to rapid exposure of sensitive data.

Existing CSPM tools are often:

- Foreign-built and SaaS-dependent
- Opaque in detection logic
- Unsuitable for controlled, on-premise, or academic environments

Nirikshak addresses this gap by providing an indigenous, transparent, and self-hosted solution.

## Features

- **Multi-Cloud Support:** Audits AWS, Azure, and GCP configurations.
- **Rule-Driven Engine:** YAML/JSON-based rules linked to CIS and NIST benchmarks.
- **IaC Scanning:** Parses Terraform plans for pre-deployment checks.
- **Agentless Operation:** Read-only access with minimal permissions.
- **Reporting:** Structured JSON and CSV exports, with future PDF support.
- **Self-Hosted:** No external data transfer or telemetry.

## Architecture

Nirikshak follows a modular, rule-driven architecture for clarity and auditability.

### Components

#### Rules Engine

- Rules defined in YAML or JSON, linked to CIS and NIST controls.
- Reusable for live cloud and IaC scans.
- Human-readable and editable, with no black-box logic.

#### Cloud Provider Adapters

- **AWS:** Uses `boto3` SDK.
- **Azure:** Uses `azure-mgmt` SDK.
- **GCP:** Uses `google-cloud` SDK.
- Collects configuration metadata with read-only permissions and normalizes data into a common schema.

#### IaC Scanner

- Parses Terraform `plan -json` output.
- Detects misconfigurations before deployment.
- Shares the same rules engine for consistency.

#### Detection and Scoring Engine

- Executes rules against normalized data.
- Assigns severity based on impact and exposure.
- Records timestamps for traceability.

#### API and Storage Layer

- **Backend:** FastAPI.
- **Storage:** SQLite for local deployments, PostgreSQL for multi-user environments.
- All data remains user-controlled.

#### Visualization and Reporting

- Web dashboard (planned).
- CIS-aligned compliance summaries.
- Exportable PDF and CSV reports.

## Tech Stack

### Core Language

- Python

### Cloud Provider SDKs

- AWS: `boto3`
- Azure: `azure-mgmt`
- GCP: `google-cloud`

### IaC Scanning

- Terraform CLI (JSON Plan)

### Rules Engine

- YAML/JSON for rule definitions
- PyYAML for parsing

### Backend API

- FastAPI

### CLI

- `argparse`, Typer

### Data Storage

- SQLite, PostgreSQL

### Dashboard

- React + Vite / Next.js / Remix.js

### Data Insights and Visualization

- Chart.js, Recharts, D3.js

### Reporting

- WeasyPrint/ReportLab (PDF), CSV Export

### Dev and Security

- Poetry (dependency management)
- Bandit (code security)
- Black + Ruff (formatting and linting)

## How It Works

1. **Initialization:** CLI command triggers scan with specified cloud provider.
2. **Configuration Collection:** Adapters gather metadata using read-only permissions.
3. **Normalization:** Data standardized into common schema.
4. **Rule Evaluation:** Rules applied to detect misconfigurations.
5. **Scoring:** Findings classified by severity and scored.
6. **Reporting:** Results exported in JSON and CSV formats.

## Prototype Workflow

The prototype demonstrates a complete scanning lifecycle:

1. **Project Initialization:** Modular setup with AWS adapter, core engine, rules, and reports.
2. **CLI Execution:** Run `python cli.py scan aws` to initiate scan.
3. **Scan Initialization:** Generate unique Scan ID, capture timestamp, collect resources.
4. **Rule Engine Execution:** Evaluate against CIS-aligned rules, detect misconfigurations.
5. **Severity Aggregation:** Score risks and provide posture visibility.
6. **Report Generation:** Produce JSON and CSV reports for auditing.

## Limitations

- **Scope:** Configuration-only auditing; no runtime behavior analysis.
- **Design:** CSPM-lite; not a full enterprise CSPM replacement.
- **Remediation:** Detection-only; manual fixes required.
- **Detection:** Rule-based; no ML or behavioral analysis.
- **Benchmarking:** Initial focus on coverage and latency; advanced benchmarking pending.

## Roadmap

### Phase 1: Core Engine Foundation

- Modular cloud adapters
- Unified normalization layer
- YAML-based rules
- Deterministic detection
- Severity scoring
- JSON/CSV reporting

### Phase 2: Integration & Coverage Expansion

- IaC scanning (Terraform)
- Expanded service coverage
- Compliance enhancements
- Benchmarking against open-source tools

### Phase 3: Platform & Deployment Layer

- Backend API
- Persistent storage
- Historical tracking
- Web dashboard
- Multi-user support

### Phase 4: Advanced Security Capabilities

- Configuration drift detection
- Risk trend analysis
- CI/CD integration
- Extended compliance mappings

## Team

**Fly High**

- **M Kishoreraj (Team Lead):** System architecture, core engine, adapters, scoring, documentation.
- **Viswaathan Chidambaram:** CIS/NIST mapping, rule validation, benchmarking.
- **Kodali Aniketh Kumar:** API, dashboard, reporting, UI, deployment testing.

## References

### Open-Source Cloud Security & CSPM Tools

- [Prowler](https://github.com/prowler-cloud/prowler) - Open-source CSPM for AWS, Azure, GCP, Kubernetes.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing.
- [Checkov](https://github.com/bridgecrewio/checkov) - IaC security scanner.
- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability and misconfiguration scanner.
- [CloudSploit](https://github.com/darkbitio/scans) - Cloud misconfiguration detection.
- [AWS Security Scanner](https://github.com/NaolMengistu/AWS-security-scanner) - Reference boto3 implementation.
- [S3Rec0n](https://github.com/Ebryx/S3Rec0n) - S3 misconfiguration scanner.

### Cloud SDKs and Technical Documentation

- [AWS boto3 SDK](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Terraform CLI](https://developer.hashicorp.com/terraform/docs)
- [Terraform JSON Plan](https://developer.hashicorp.com/terraform/internals/json-format)

### Compliance Standards & Security Benchmarks

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Microsoft Azure Benchmark](https://www.cisecurity.org/benchmark/azure)
- [CIS Google Cloud Platform Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

### Supporting Frameworks & Libraries

- [Typer](https://typer.tiangolo.com/) - Python CLI framework.
- [PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation) - YAML parsing.
- [FastAPI](https://fastapi.tiangolo.com/) - Backend API.
- [WeasyPrint](https://weasyprint.org/) - PDF reporting.

### Comparative & Industry Context

- [Top Open-Source CSPM Tools](https://aimultiple.com/open-source-cspm)
- [Cloud Security Framework for Indian Banking](https://www.idrbt.ac.in/wp-content/uploads/2022/07/Cloud-Security-Framework-2013.pdf)
