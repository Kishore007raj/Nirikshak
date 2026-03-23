"""
Azure Network Security Groups collector.

Fetches details of all network security groups in an Azure subscription
using NetworkManagementClient.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from azure.core.exceptions import AzureError


def collect_network_security_groups(
    subscription_id: str,
) -> List[Dict[str, Any]]:
    """Collect all network security groups from the Azure subscription.

    Args:
        subscription_id: Azure subscription ID.

    Returns:
        List of NSG dictionaries with name and inbound rules.
    """
    from azure.utils.azure_helpers import (
        extract_nsg_rules,
        safe_get,
        get_network_client,
    )

    nsgs = []

    try:
        client = get_network_client(subscription_id)

        # List all NSGs
        for nsg in client.network_security_groups.list_all():
            try:
                nsg_data = {
                    "id": safe_get(nsg, "id", "unknown"),
                    "name": safe_get(nsg, "name", "unknown"),
                    "rules": extract_nsg_rules(nsg),
                }
                nsgs.append(nsg_data)

            except Exception as e:
                # Skip NSGs with collection errors
                print(f"Warning: Failed to collect NSG details: {e}")
                continue

    except AzureError as e:
        print(f"Error collecting network security groups: {e}")
    except Exception as e:
        print(f"Unexpected error collecting network security groups: {e}")

    return nsgs
