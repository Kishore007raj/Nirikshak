# Nirikshak - Cloud Misconfiguration Scanner

Nirikshak is a self-hosted, rule-driven cloud misconfiguration scanner for AWS, Azure, and GCP. It detects high-impact security issues using transparent rules mapped to CIS and NIST benchmarks, with no SaaS dependency.

---

## What it does

Nirikshak identifies security misconfigurations in cloud infrastructure. It scans AWS S3, Azure Blob, and GCP buckets for public exposure. It checks security groups for open management ports (SSH/RDP). It audits IAM policies for excessive permissions. The tool normalizes provider data into a single schema and evaluates it against YAML-based rules mapped to CIS and NIST benchmarks.

---

## Why it exists

Traditional CSPM tools often require SaaS connectivity or only support live infrastructure. Nirikshak fills three gaps:
1. **Air-gapped execution**: Runs fully offline with no external telemetry.
2. **Unified logic**: Uses identical rules for both live cloud resources and Terraform JSON plans.
3. **Transparent attribution**: Maps every finding directly to a specific CIS/NIST control without abstract scoring layers.

---

## Features

- **Multi-Cloud Audit**: Supports AWS, Azure, and GCP via native SDKs.
- **IaC Scanning**: Evaluates Terraform `plan -json` files before deployment.
- **Rules-as-Code**: Detections defined in human-readable YAML.
- **Risk Mapping**: Direct attribution to CIS and NIST frameworks.
- **Local Persistence**: Stores scan history in a local SQLite database.
- **Audit Reports**: Generates PDF and CSV summaries for compliance teams.

---

## Architecture

Nirikshak uses a layered pipeline.

<img src="docs/images/nirikshak-system-workflow.png" width="900"/>

### Components

#### Input Layer

* Live cloud configurations (AWS, Azure, GCP)
* Terraform `plan -json` output

#### Collection Layer

* AWS: `boto3`
* Azure: `azure-mgmt`
* GCP: `google-cloud`
* Extracts configuration metadata using read-only access

#### Normalization Layer

* Converts provider-specific formats into a unified schema
* Ensures rule consistency across clouds

#### Rules Engine

* YAML/JSON rules mapped to CIS/NIST
* No abstraction layer; logic is explicit
* Same rules reused for IaC and live scans

#### Detection and Scoring Engine

* Evaluates normalized data
* Assigns severity based on exposure and impact

#### API and Storage Layer

* FastAPI backend
* SQLite (local) / PostgreSQL (single-node use)
* No external communication

#### Visualization and Reporting

* Real-time dashboard (WebSocket updates)
* Export: JSON, CSV, PDF
* Scan history tracking

---

## How It Works

1. User selects cloud provider or Terraform plan
2. Scan starts via CLI or API
3. Resources collected using adapters
4. Data normalized into internal schema
5. Rules executed against configurations
6. Misconfigurations detected and scored
7. Results stored locally
8. Reports generated and dashboard updated

---

## Quick Start

### 1. Install prerequisites

Make sure these are installed and working:

```bash
docker --version
docker-compose --version
python --version
git --version
```

### 2. Configure cloud providers (if used)

#### Azure

```bash
az login
az account show
```

#### AWS

```bash
aws configure
aws sts get-caller-identity
```

#### GCP

```bash
gcloud auth login
gcloud config set project <your-project-id>
gcloud auth list
```

### 3. Clone the repository

```bash
git clone <Nirikshak>
cd <Nirikshak>
```

### 4. Set environment variables (if required)

```bash
cp .env.example .env
```

Add keys if your system uses them:

```
AZURE_API_KEY=your_key
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_key
GCP_PROJECT_ID=your_project
```

### 5. Start the system

```bash
docker-compose up --build
```

The backend runs at:
`http://localhost:8000`

API docs (if enabled):
`http://localhost:8000/docs`

### 6. Verify containers are running

```bash
docker ps
```

You should see `nirikshak_app` with status **Up**.

### 7. Verify detection system

Run the validation suite:

```bash
python validate.py
```

This checks parsing, detection logic, and scoring.

### 8. Check logs

```bash
docker logs -f nirikshak_app
```

Use this to monitor scans and debug errors.

### 9. Test the system

Example request:

```bash
curl -X POST http://localhost:8000/analyze \
-H "Content-Type: application/json" \
-d '{"email":"Suspicious login attempt. Click here."}'
```

### 10. Stop the system

```bash
docker-compose down
```
---

## Usage

1. **Authenticate on host**: Run `aws configure`, `az login`, or `gcloud auth login`.
2. **Select Provider**: Use the UI to choose between AWS, Azure, or GCP.
3. **Execute Scan**: Trigger the collection engine.
4. **Download Report**: Export findings to PDF or CSV from the results table.

---

## Example Output

Findings use a flat JSON structure for easy integration:

```json
{
  "resource_id": "production-data-storage",
  "resource_type": "storage_account",
  "severity": "CRITICAL",
  "description": "Public read access is enabled.",
  "impact": "Unauthenticated data exfiltration.",
  "fix_suggestion": "Update ACL to private.",
  "compliance": "CIS Azure 3.1"
}
```

---

## API

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/scan/{provider}` | POST | Triggers a new infrastructure scan |
| `/results` | GET | Returns the latest findings |
| `/history` | GET | Lists past scan summaries |
| `/download/{id}` | GET | Exports a specific scan report |

---

## Project Structure

```text
api/       # FastAPI endpoints and WebSocket handlers
core/      # Normalization and rule evaluation engine
aws/       # AWS adapter (boto3)
azure/     # Azure adapter (azure-mgmt)
gcp/       # GCP adapter (google-cloud)
rules/     # YAML detection definitions
dashboard/ # Frontend dashboard (HTML/JS)
```

---

## Tech Stack

### Current Tech Stack

1. **Core Language:** Python 3.10+
2. **Backend API:** FastAPI
3. **Cloud SDKs:** AWS (`boto3`), Azure (`azure-mgmt`), GCP (`google-cloud`)
4. **IaC Scanning:** Terraform JSON plan parsing
5. **Rules Engine:** YAML/JSON rules, PyYAML
6. **CLI:** argparse, Typer
7. **Data Storage:** SQLite (default), PostgreSQL (single-node use)
8. **Frontend / Dashboard:** HTML, CSS, Vanilla JS
9. **Data Visualization:** Chart.js (limited use)
10. **Reporting:** PDF (ReportLab / WeasyPrint), CSV
11. **Realtime:** WebSockets
12. **Dev & Security Tools:** Poetry, Bandit, Black, Ruff

---

### Planned Tech Stack

1. **Core Platform Expansion:** Modular adapters for deeper cloud service coverage
2. **IaC Expansion:** CloudFormation and additional IaC tools
3. **CI/CD Integration:** Pipeline-based pre-deployment scanning
4. **Backend Evolution:** Persistent, multi-user PostgreSQL backend
5. **Drift Detection:** Lightweight monitoring agent
6. **Compliance Expansion:** Industry-specific standards beyond CIS/NIST
7. **Frontend Upgrade:** React with Tailwind / Chakra UI
8. **Advanced Visualization:** Recharts, D3.js
9. **Realtime Enhancements:** Alerts and live risk tracking
10. **Detection Enhancements:** Optional ML-based anomaly filtering

---

## Limitations

- **Read-Only**: Detects issues but does not modify infrastructure.
- **Local Scope**: Designed for single-node deployment; no distributed scanning.
- **Latency**: Large environments may experience collection delays based on API rate limits.
- **Persistence**: Default SQLite is not suitable for high-concurrency environments.

---

## Roadmap

- **Drift Detection**: Identify state changes between historical scans.
- **CI/CD Integration**: CLI plugin for GitHub Actions and GitLab CI.
- **Advanced Alerting**: PagerDuty and Slack webhook integrations.
- **Custom Rules**: Web-based editor for YAML rule creation.

---

## Team

* **M Kishoreraj (Team Lead):** Architecture, engine, adapters, scoring
* **Viswanaathan Chidambaram:** CIS/NIST mapping, validation
* **Kodali Aniketh Kumar:** API, dashboard, reporting

---

## References

### Open-Source CSPM

* [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)
* [https://github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite)
* [https://github.com/bridgecrewio/checkov](https://github.com/bridgecrewio/checkov)

### Cloud & IaC

* [https://boto3.amazonaws.com/v1/documentation/api/latest/index.html](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
* [https://developer.hashicorp.com/terraform/docs](https://developer.hashicorp.com/terraform/docs)
* [https://developer.hashicorp.com/terraform/internals/json-format](https://developer.hashicorp.com/terraform/internals/json-format)

### Compliance

* [https://www.cisecurity.org/benchmark/amazon_web_services](https://www.cisecurity.org/benchmark/amazon_web_services)
* [https://www.cisecurity.org/benchmark/azure](https://www.cisecurity.org/benchmark/azure)
* [https://www.cisecurity.org/benchmark/google_cloud_computing_platform](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
* [https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---
## License

This project is released under the [MIT License](LICENSE)

---