# Azure Scanner - Developer Quick Reference

## Project Structure

```
Nirikshak/
├── azure/                              # Azure-specific code
│   ├── adapter.py                      # AzureAdapter orchestrator
│   ├── collectors/                     # Data collection layer
│   │   ├── virtual_machines.py         # Fetch VMs
│   │   ├── storage_accounts.py         # Fetch storage
│   │   └── network_security_groups.py  # Fetch NSGs
│   ├── normalizers/                    # Data transformation
│   │   └── azure_normalizer.py         # Convert to Resource format
│   └── utils/
│       └── azure_helpers.py            # Helper functions
├── core/                               # Core scanning engine
│   ├── engine.py                       # Rule evaluation
│   ├── loader.py                       # Rule loading
│   ├── models.py                       # Data models (Resource, Finding)
│   ├── runner.py                       # Scan orchestration
│   └── severity.py                     # Scoring logic
├── utils/
│   └── config_loader.py                # Configuration management
├── rules/
│   └── azure/                          # Security rules
│       ├── storage.yaml                # Storage rules
│       ├── network.yaml                # NSG rules
│       ├── compute.yaml                # VM rules
│       ├── identity.yaml               # IAM rules
│       └── logging.yaml                # Logging rules
├── reports/                            # Report generation
│   ├── json_report.py                  # JSON output
│   └── csv_report.py                   # CSV output
├── cli/
│   └── cli.py                          # Command-line interface
├── configs/
│   └── settings.yaml                   # Azure subscription ID
├── output/                             # Report output directory
│   ├── nirikshak_report.json           # JSON report
│   └── nirikshak_report.csv            # CSV report
└── cloud/
    └── scanner.py                      # Provider dispatcher
```

## Key Classes & Functions

### Azure Adapter

```python
from azure.adapter import AzureAdapter

# Usage
adapter = AzureAdapter()
resources = adapter.collect_and_normalize()
# Returns: List[Resource]
```

### Collectors (One for each resource type)

```python
from azure.collectors.virtual_machines import collect_virtual_machines
from azure.collectors.storage_accounts import collect_storage_accounts
from azure.collectors.network_security_groups import collect_network_security_groups

# Each returns Dict[str, Any] with specific fields
vms = collect_virtual_machines(subscription_id)
# [{"id": "...", "name": "...", "os_type": "...", ...}]

storage = collect_storage_accounts(subscription_id)
# [{"name": "...", "public_access": False, "encryption": True}]

nsgs = collect_network_security_groups(subscription_id)
# [{"name": "...", "rules": [{"port": 22, "source": "0.0.0.0/0"}]}]
```

### Normalizer

```python
from azure.normalizers.azure_normalizer import normalize_azure_resources

resources = normalize_azure_resources(vms, storage, nsgs)
# Returns: List[Resource] with type, resource_id, config
```

### Rule Engine

```python
from core.engine import run_engine
from core.loader import load_rules

rules = load_rules()
findings = run_engine(resources, rules)
# Returns: List[Dict] with rule_id, severity, resource_id, etc.
```

### Config Loader

```python
from utils.config_loader import get_azure_subscription_id

subscription_id = get_azure_subscription_id()
# Reads from configs/settings.yaml
```

## Data Models

### Resource (Core)

```python
@dataclass
class Resource:
    resource_type: str          # "vm", "storage_account", "network_security_group"
    resource_id: str            # Unique identifier
    region: str                 # Azure region
    provider: str               # "azure"
    config: Dict[str, Any]      # Resource-specific config
```

### Finding (Output)

```python
@dataclass
class Finding:
    rule_id: str               # "STORAGE_PUBLIC", "NSG_SSH_OPEN"
    title: str                 # Human-readable title
    severity: str              # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    provider: str              # "azure"
    resource_id: str           # Resource identifier
    resource_type: str         # Resource type
    region: str                # Azure region
    cis_reference: str         # CIS benchmark reference
    timestamp: str             # ISO format timestamp
    details: str               # Additional info
```

## Rule Format (YAML)

```yaml
- id: RULE_ID # Unique identifier
  title: Rule Title # Human-readable name
  resource_type: resource_type # vm | storage_account | network_security_group
  severity: CRITICAL # CRITICAL | HIGH | MEDIUM | LOW
  cis_reference: "X.Y" # CIS benchmark reference
  check: "field == value" # Simple equality check
  description: | # Detailed explanation
    Multi-line description
```

## Extension Points

### Adding a New Collector

1. Create file: `azure/collectors/new_resource.py`
2. Implement: `collect_new_resources(subscription_id: str) -> List[Dict]`
3. Update: `azure/adapter.py` to call new collector
4. Update: `azure/normalizers/azure_normalizer.py` to normalize

### Adding a New Rule

1. Create/edit YAML: `rules/azure/category.yaml`
2. Define fields: id, title, resource_type, severity, check
3. Rule auto-loads on next scan

### Modifying Facts Calculation

Edit: `core/engine.py` → `_compute_facts()` function

- Add new derived facts based on config fields
- These facts can be checked in rule `check` field

## Azure SDK Classes Used

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
```

## Import Paths (from project root)

```python
# Azure components
from azure.adapter import AzureAdapter
from azure.collectors.virtual_machines import collect_virtual_machines
from azure.normalizers.azure_normalizer import normalize_azure_resources
from azure.utils.azure_helpers import get_compute_client

# Core components
from core.models import Resource, Finding
from core.engine import run_engine
from core.loader import load_rules
from core.runner import run_scan
from core.severity import calculate_risk_score

# Utilities
from utils.config_loader import get_azure_subscription_id

# Reports
from reports.json_report import generate_json_report
from reports.csv_report import generate_csv_report
```

## Severity Weights (risk calculation)

```python
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}

# Example: 1 CRITICAL + 2 HIGH = 10 + 7 + 7 = 24
```

## Configuration

### settings.yaml

```yaml
# Azure subscription ID
azure subscription_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Optional AWS (for AWS scans)
aws:
  region: us-east-1
  profile: default

# Optional GCP (for GCP scans)
gcp:
  project_id: "project-id"
  credentials_file: "/path/to/credentials.json"
```

## Common Commands

```bash
# Demo scan (no auth needed)
python -m cli.cli demo azure

# Live scan (auth required)
az login
python -m cli.cli scan azure

# Custom output paths
python -m cli.cli scan azure \
  --output-json report.json \
  --output-csv report.csv

# Check what's loaded
python -c "from core.loader import load_rules; rules = load_rules(); \
print(f'Loaded {len(rules)} rules'); print([r['id'] for r in rules if r['resource_type'] == 'storage_account'])"
```

## Testing Tips

### Test Collectors Independently

```python
from azure.collectors.virtual_machines import collect_virtual_machines
vms = collect_virtual_machines("your-subscription-id")
print(f"Found {len(vms)} VMs")
```

### Test Normalizer

```python
from azure.normalizers.azure_normalizer import normalize_virtual_machines
resources = normalize_virtual_machines([{"id": "1", "name": "vm1", ...}])
print(f"Normalized resource type: {resources[0].resource_type}")
```

### Test Rule Engine

```python
from core.engine import run_engine
from core.loader import load_rules
from core.models import Resource

resource = Resource(resource_type="storage_account", resource_id="test", region="eastus",
                   provider="azure", config={"public_access": True, "encryption": False})
rules = load_rules()
findings = run_engine([resource], rules)
print(f"Found {len(findings)} issues")
```

## Debugging

### Enable Verbose Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check Loaded Rules

```python
from core.loader import load_rules
rules = load_rules()
for rule in rules:
    if rule['resource_type'] == 'storage_account':
        print(f"Rule: {rule['id']} - Check: {rule['check']}")
```

### Inspect Resource Config

```python
from azure.adapter import AzureAdapter
adapter = AzureAdapter()
resources = adapter.collect_and_normalize()
for r in resources:
    if r.resource_type == 'storage_account':
        print(f"Config: {r.config}")
```

## Performance Characteristics

- **Collection**: O(n) where n = resources
- **Normalization**: O(n) linear
- **Rule Evaluation**: O(n × r) where r = rules (~5)
- **demo mode**: < 1 second (3 sample resources)
- **live mode, small subscription**: 1-2 minutes (10-50 resources)
- **live mode, large subscription**: 5-10 minutes (1000+ resources)

## No-Crash Principles

1. All collector functions return empty list on error
2. All helper functions have default/fallback values
3. Missing fields → None or False (safe defaults)
4. Invalid YAML → Skip rule with warning
5. SDK errors → Logged, continue processing
6. Empty resource lists → Valid (0 findings)

---

**Last Updated**: March 20, 2026
