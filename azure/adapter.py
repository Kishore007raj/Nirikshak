"""
Azure adapter.

Orchestrates collectors and normalizers to gather and normalize
Azure resources for security scanning.
use the AzureAdapter class to collect and normalize Azure resources. The collect_azure_resources function is deprecated and should not be used in new code.
"""

from __future__ import annotations

from typing import List, Optional

from core.models import Resource
from utils.config_loader import get_azure_subscription_id

from azure.collectors.virtual_machines import collect_virtual_machines
from azure.collectors.storage_accounts import collect_storage_accounts
from azure.collectors.network_security_groups import (
    collect_network_security_groups,
)
from azure.normalizers.azure_normalizer import normalize_azure_resources


class AzureAdapter:
    """Adapter for collecting and normalizing Azure resources."""

    def __init__(self, subscription_id: Optional[str] = None):
        """Initialize Azure adapter.

        Args:
            subscription_id: Azure subscription ID. If not provided,
                           will be loaded from configuration.
        """
        if subscription_id:
            self.subscription_id = subscription_id
        else:
            self.subscription_id = get_azure_subscription_id()

        if not self.subscription_id:
            raise ValueError("Azure subscription ID is required")

    def collect_and_normalize(self) -> List[Resource]:
        """Collect all Azure resources and normalize them.

        Returns:
            List of normalized Resource objects.
        """
        # Collect raw data from Azure
        try:
            vms = collect_virtual_machines(self.subscription_id)
        except Exception as e:
            print(f"VM collection failed: {e}")
            vms = []

        try:
            storage_accounts = collect_storage_accounts(self.subscription_id)
        except Exception as e:
            print(f"Storage collection failed: {e}")
            storage_accounts = []

        try:
            nsgs = collect_network_security_groups(self.subscription_id)
        except Exception as e:
            print(f"NSG collection failed: {e}")
            nsgs = []

        # Normalize into canonical format
        resources = normalize_azure_resources(vms, storage_accounts, nsgs)

        return resources

#this one is just for showcase and testing of mock up data, not to be used in production code. Please use AzureAdapter class instead.
def collect_azure_resources(region: Optional[str] = None, profile: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect normalized Azure resources.

    THIS FUNCTION IS DEPRECATED. Use AzureAdapter class instead.

    Args:
        region: Region parameter (ignored).
        profile: Profile parameter (ignored).
        mode: "demo" for demo data, "real" for live Azure scan.

    Returns:
        List of normalized Resource objects.
    """
    resources: List[Resource] = []

    if mode == "demo":
        # Simple demo data for demonstration purposes
        resources.append(
            Resource(
                resource_type="storage_account",
                resource_id="demo-storage-account",
                region=region or "global",
                provider="azure",
                config={
                    "name": "demo-storage",
                    "public_access": True,
                    "encryption": False,
                },
            )
        )

        resources.append(
            Resource(
                resource_type="network_security_group",
                resource_id="demo-nsg",
                region=region or "global",
                provider="azure",
                config={
                    "name": "demo-nsg",
                    "inbound_rules": [
                        {
                            "port": 22,
                            "source": "0.0.0.0/0",
                        },
                        {
                            "port": 3389,
                            "source": "0.0.0.0/0",
                        }
                    ]
                },
            )
        )

        resources.append(
            Resource(
                resource_type="vm",
                resource_id="demo-vm",
                region=region or "eastus",
                provider="azure",
                config={
                    "name": "demo-vm",
                    "os_type": "Linux",
                    "encryption_enabled": False,
                },
            )
        )
    else:
        # Real Azure scan
        try:
            adapter = AzureAdapter()
            resources = adapter.collect_and_normalize()
        except Exception as e:
            print(f"Error collecting Azure resources: {e}")

    return resources