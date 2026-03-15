"""Azure adapter stubs for demo mode."""

from __future__ import annotations

from typing import List, Optional

from core.models import Resource


def collect_azure_resources(region: Optional[str] = None, profile: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect normalized Azure resources.

    Currently only demo mode is supported. This function can be extended to use
    azure-mgmt SDKs for real scans.
    """

    resources: List[Resource] = []

    if mode != "demo":
        # Real Azure scanning not yet implemented.
        return resources

    # Simple demo data that mirrors AWS demo resources.
    # In a full implementation, demo_data would include Azure-specific examples.
    resources.append(
        Resource(
            resource_type="storage_account",
            resource_id="demo-storage-account",
            region=region or "global",
            provider="azure",
            config={
                "public_access_enabled": True,
                "encryption_enabled": False,
                "versioning_enabled": False,
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
                "inbound_rules": [
                    {
                        "port": 22,
                        "cidr": "0.0.0.0/0",
                    }
                ]
            },
        )
    )

    return resources
