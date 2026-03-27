# Azure Cloud Security Scanner - Setup & Usage Guide

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:

- `azure-identity` - For Azure authentication
- `azure-mgmt-compute` - For VM management
- `azure-mgmt-network` - For NSG management
- `azure-mgmt-storage` - For storage account management
- `typer` - For CLI
- `pyyaml` - For configuration

### 2. Configure Azure Subscription

Edit `configs/settings.yaml` and set your subscription ID:

```yaml
# This file contains the settings for Nirikshak, including Azure subscription details.
azure subscription_id: "YOUR-SUBSCRIPTION-ID-HERE"
```

### 3. Authenticate with Azure

For **demo mode** (no authentication needed):

```bash
python -m cli.cli demo azure
```

For **live scanning** (requires Azure authentication):

```bash
# Login with Azure CLI first
az login

# Or use any DefaultAzureCredential method:
# - Azure CLI
# - Azure PowerShell
# - Azure SDK environment variables
# - Managed Identity (in Azure)

# Then run the scan
python -m cli.cli scan azure
```

## Usage

### Demo Mode (Recommended for Testing)

```bash
python -m cli.cli demo azure
```

**Output:**

- Console findings with severity levels
- Risk score calculation
- `output/nirikshak_report.json` - Detailed JSON report
- `output/nirikshak_report.csv` - Spreadsheet-friendly CSV

**Sample Output:**

```
[INFO] Scan completed
[INFO] Scan ID: a1b2c3d4-e5f6-7890-...
[INFO] Provider: azure
[INFO] Mode: demo
[INFO] Timestamp: 2026-03-20T...
[INFO] CRITICAL: 1
[INFO] HIGH: 2
[INFO] MEDIUM: 0
[INFO] LOW: 0
[INFO] Risk score: 24
```

### Live Mode (Production Scanning)

```bash
python -m cli.cli scan azure
```

**Security Checks Performed:**

| Check                 | Severity | Type    | Description                |
| --------------------- | -------- | ------- | -------------------------- |
| STORAGE_PUBLIC        | CRITICAL | Storage | Blob public access enabled |
| STORAGE_NO_ENCRYPTION | HIGH     | Storage | No encryption at rest      |
| NSG_OPEN_ALL          | CRITICAL | Network | All ports open to world    |
| NSG_SSH_OPEN          | HIGH     | Network | SSH (port 22) exposed      |
| NSG_RDP_OPEN          | HIGH     | Network | RDP (port 3389) exposed    |
| VM_NO_ENCRYPTION      | HIGH     | Compute | Disk encryption disabled   |

### Custom Output Locations

```bash
python -m cli.cli scan azure \
  --output-json /path/to/report.json \
  --output-csv /path/to/report.csv
```

## Reports

### JSON Report Format

File: `output/nirikshak_report.json`

```json
{
    "scan_id": "550e8400-e29b-41d4-a716-...",
    "scan_timestamp": "2026-03-20T12:34:56.789012",
    "provider": "azure",
    "mode": "demo",
    "risk_score": 24,
    "summary": {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 0
    },
    "total_findings": 3,
    "findings": [
        {
            "rule_id": "STORAGE_PUBLIC",
            "title": "Storage Account Public Access Enabled",
            "severity": "CRITICAL",
            "cis_reference": "3.6",
            "resource_id": "demo-storage-account",
            "resource_type": "storage_account",
            "region": "global",
            "provider": "azure",
            "details": "Rule 'STORAGE_PUBLIC' matched for resource 'demo-storage-account'",
            "timestamp": "2026-03-20T12:34:56.789012"
        },
        ...
    ]
}
```

### CSV Report Format

File: `output/nirikshak_report.csv`

```csv
rule_id,severity,resource_id,provider,cis_reference,timestamp
STORAGE_PUBLIC,CRITICAL,demo-storage-account,azure,3.6,2026-03-20T...
NSG_SSH_OPEN,HIGH,demo-nsg,azure,6.3,2026-03-20T...
```

## Risk Scoring

Risk score is calculated by summing severity weights:

- **CRITICAL**: 10 points
- **HIGH**: 7 points
- **MEDIUM**: 4 points
- **LOW**: 1 point

**Example Calculation:**

```
1 CRITICAL finding (10) + 2 HIGH findings (7×2) + 0 MEDIUM + 0 LOW
= 10 + 14 + 0 + 0 = 24
```

## Architecture

### Data Flow

```
┌─────────────────┐
│  Azure SDK      │
│  Subscription   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Collectors                      │
│ • VirtualMachines              │
│ • StorageAccounts              │
│ • NetworkSecurityGroups        │
└────────┬────────────────────────┘
         │ Raw Azure data
         ▼
┌─────────────────────────────────┐
│ Adapter                         │
│ AzureAdapter.collect_normalize()│
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Normalizer                      │
│ → Resource (canonical format)   │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Rule Engine                     │
│ Evaluate ~5 security rules      │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Findings Aggregator             │
│ Calculate risk score            │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Reports                         │
│ JSON + CSV + Console output     │
└─────────────────────────────────┘
```

## Troubleshooting

### Error: "Azure subscription_id not found"

**Solution:** Set `azure subscription_id` in `configs/settings.yaml`

### Error: "Authentication failed"

**Solution:** Run `az login` before scanning with live mode

### No findings detected

**Possible causes:**

1. Empty subscription (no resources)
2. All resources are properly configured
3. Rules not matching resource types

**Debug:** Check JSON report for `total_findings` count

### Missing resources in scan

**Causes:**

1. No read permissions on subscription
2. Resources in different subscription (change config)
3. API errors (check console logs)

**Solution:** Check Azure RBAC permissions

## Performance

- **Large subscriptions** (1000+ resources): May take 5-10 minutes
- **Small subscriptions** (< 100 resources): Usually < 1 minute
- **Demo mode**: < 1 second

### Optimization Tips

1. Demo mode for quick testing
2. Consider separate scans per resource type
3. Run during off-peak hours
4. Set appropriate Azure role (Reader sufficient)

## Security Best Practices

1. **Authentication**: Use DefaultAzureCredential (best practice)
2. **Permissions**: Use least-privilege Reader role
3. **Reports**: Store reports in secure location
4. **Credentials**: Never commit credentials to repos
5. **Automation**: Use Managed Identity in Azure for CI/CD

## Integration with CI/CD

### GitHub Actions Example

```yaml
- name: Run Azure Security Scan
  run: |
    az login --service-principal -u ${{ secrets.AZURE_CLIENT_ID }} \
      -p ${{ secrets.AZURE_CLIENT_SECRET }} -t ${{ secrets.AZURE_TENANT_ID }}
    python -m cli.cli scan azure \
      --output-json azure-scan-report.json \
      --output-csv azure-scan-report.csv

- name: Upload Reports
  uses: actions/upload-artifact@v2
  with:
    name: azure-scan-reports
    path: |
      azure-scan-report.json
      azure-scan-report.csv
```

## Advanced Usage

### Custom Rules

1. Create new YAML files in `rules/azure/`
2. Follow the rule format (see `rules/azure/storage.yaml`)
3. Rules auto-load on next scan

### Rule Format

```yaml
- id: RULE_ID
  title: Rule Title
  resource_type: resource_type_name
  severity: CRITICAL|HIGH|MEDIUM|LOW
  cis_reference: "X.Y"
  check: "field == value"
  description: Detailed description
```

## Support & Documentation

- Implementation details: See `IMPLEMENTATION_SUMMARY.md`
- Project structure: See `README.md`
- Rule definitions: See `rules/azure/`
- Configuration: See `configs/settings.yaml`

## Exit Codes

- `0` - Scan completed successfully
- `1` - Authentication failed
- `2` - Configuration error
- `3` - No subscription ID configured

---

**Version**: 1.0
**Last Updated**: March 20, 2026
**Status**: Production Ready ✅
