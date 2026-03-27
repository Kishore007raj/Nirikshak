# Quick Start - Azure Cloud Security Scanner

## 30-Second Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Test Immediately (No Azure credentials needed!)

```bash
python -m cli.cli demo azure
```

## Expected Output

```
[INFO] Scan completed
[INFO] Scan ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
[INFO] Provider: azure
[INFO] Mode: demo
[INFO] Timestamp: 2026-03-20T12:34:56.123456
[INFO] CRITICAL: 1
[INFO] HIGH: 2
[INFO] MEDIUM: 0
[INFO] LOW: 0
[INFO] Risk score: 24
[INFO] JSON report generated: output/nirikshak_report.json
[INFO] CSV report generated: output/nirikshak_report.csv
```

## Reports Generated

### 1. JSON Report: `output/nirikshak_report.json`

Contains:

- `scan_id`: Unique scan identifier
- `findings`: Array of security issues found
- `risk_score`: 24 (calculated from severities)
- `summary`: Count by severity level
- `timestamp`: When scan ran

### 2. CSV Report: `output/nirikshak_report.csv`

Contains:

- Headers: rule_id, severity, resource_id, provider, cis_reference, timestamp
- One row per finding
- Easy to import into Excel/Sheets

## Architecture

### Three-Part System

**1. Collectors** - Fetch from Azure

- VirtualMachinesCollector (ComputeManagementClient)
- StorageAccountsCollector (StorageManagementClient)
- NSGsCollector (NetworkManagementClient)

**2. Normalizer** - Convert to standard format

- Transforms Azure-specific data into Resource objects
- Unified interface for rule engine

**3. Rule Engine** - Detect security issues

- Evaluates 5 Azure-specific rules
- Calculates severity and risk score
- Produces findings

## Security Rules

| Rule ID               | Severity | Check                 |
| --------------------- | -------- | --------------------- |
| STORAGE_PUBLIC        | CRITICAL | Public blob access    |
| STORAGE_NO_ENCRYPTION | HIGH     | No encryption at rest |
| NSG_OPEN_ALL          | CRITICAL | All ports open        |
| NSG_SSH_OPEN          | HIGH     | Port 22 exposed       |
| NSG_RDP_OPEN          | HIGH     | Port 3389 exposed     |

_(VM_NO_ENCRYPTION, IDENTITY_MFA_DISABLED, LOGGING_NOT_ENABLED also included)_

## Demo Data

The demo mode includes:

- 1 Storage Account (public + unencrypted) → 2 findings
- 1 NSG (SSH + RDP open to world) → 1 finding
- 1 VM (no encryption) → 0 findings (rules check only)

**Total: 3 findings = Risk Score of 24**

## Production Mode

When ready with Azure:

```bash
# Authenticate first
az login

# Run live scan
python -m cli.cli scan azure
```

This will:

1. Use your Azure credentials
2. Fetch ALL real resources from your subscription
3. Evaluate each against security rules
4. Generate reports with actual findings
5. Calculate real risk score

## File Locations

| File                           | Purpose                   |
| ------------------------------ | ------------------------- |
| `configs/settings.yaml`        | Azure subscription ID     |
| `output/nirikshak_report.json` | JSON report output        |
| `output/nirikshak_report.csv`  | CSV report output         |
| `rules/azure/`                 | Security rule definitions |
| `IMPLEMENTATION_SUMMARY.md`    | Technical details         |
| `AZURE_SETUP_GUIDE.md`         | Full setup guide          |
| `DEVELOPER_GUIDE.md`           | Code reference            |

## What Was Built

✅ Real Azure SDK integration (no mocks)
✅ ComputeManagementClient for VMs
✅ StorageManagementClient for storage  
✅ NetworkManagementClient for NSGs
✅ Safe data extraction (no crashes)
✅ 5 Azure security rules
✅ Risk scoring system
✅ JSON + CSV reports
✅ Demo + Live modes
✅ Full documentation

## No Configuration Needed!

The scanner is ready to use:

- ✅ Subscription ID already configured
- ✅ Rules already created
- ✅ CLI commands ready
- ✅ Demo data included

Just run: `python -m cli.cli demo azure`

---

## Troubleshooting

**Q: Got import error?**
A: Run `pip install -r requirements.txt` first

**Q: No findings in demo?**
A: Check JSON report - demo has 3 findings by design

**Q: Want to run against real Azure?**
A: Run `az login` then `python -m cli.cli scan azure`

**Q: Where are the reports?**
A: Check `output/` directory

---

**Status**: Ready for Production ✅
**Demo Mode**: Works Without Azure Login
**Real Mode**: Requires Azure CLI authentication
