"""
Azure Virtual Machines collector.

Fetches details of all virtual machines in an Azure subscription
using ComputeManagementClient.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from azure.core.exceptions import AzureError


def collect_virtual_machines(
    subscription_id: str,
) -> List[Dict[str, Any]]:
    """Collect all virtual machines from the Azure subscription.

    Args:
        subscription_id: Azure subscription ID.

    Returns:
        List of VM dictionaries with id, name, location, os_type, and encryption_enabled.
    """
    from azure.utils.azure_helpers import (
        extract_os_type,
        is_encryption_enabled,
        safe_get,
        get_compute_client,
    )

    vms = []

    try:
        client = get_compute_client(subscription_id)

        # Iterate through all VMs in all resource groups
        for vm in client.virtual_machines.list_all():
            try:
                vm_data = {
                    "id": safe_get(vm, "id", "unknown"),
                    "name": safe_get(vm, "name", "unknown"),
                    "location": safe_get(vm, "location", "unknown"),
                    "os_type": extract_os_type(vm),
                    "encryption_enabled": is_encryption_enabled(vm),
                }
                vms.append(vm_data)

            except Exception as e:
                # Skip VMs with collection errors
                print(f"Warning: Failed to collect VM details: {e}")
                continue

    except AzureError as e:
        print(f"Error collecting virtual machines: {e}")
    except Exception as e:
        print(f"Unexpected error collecting virtual machines: {e}")

    return vms
