"""
Azure resource normalizer.

Converts raw Azure SDK data into the canonical Resource format
used by the rule engine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.models import Resource


def normalize_virtual_machines(
    vms: List[Dict[str, Any]],
) -> List[Resource]:
    """Normalize VM data into Resource objects.

    Args:
        vms: List of VM dictionaries from collector.

    Returns:
        List of Resource objects.
    """
    resources = []

    for vm in vms:
        resource = Resource(
            resource_type="vm",
            resource_id=vm.get("id", "unknown"),
            region=vm.get("location", "unknown"),
            provider="azure",
            config={
                "name": vm.get("name", ""),
                "os_type": vm.get("os_type", "Unknown"),
                "encryption_enabled": vm.get("encryption_enabled", False),
            },
        )
        resources.append(resource)

    return resources


def normalize_storage_accounts(
    accounts: List[Dict[str, Any]],
) -> List[Resource]:
    """Normalize storage account data into Resource objects.

    Args:
        accounts: List of storage account dictionaries from collector.

    Returns:
        List of Resource objects.
    """
    resources = []

    for account in accounts:
        resource = Resource(
            resource_type="storage_account",
            resource_id=account.get("id", "unknown"),
            region="global",
            provider="azure",
            config={
                "name": account.get("name", ""),
                "public_access": account.get("public_access", False),
                "encryption": account.get("encryption", False),
            },
        )
        resources.append(resource)

    return resources


def normalize_network_security_groups(
    nsgs: List[Dict[str, Any]],
) -> List[Resource]:
    """Normalize NSG data into Resource objects.

    Args:
        nsgs: List of NSG dictionaries from collector.

    Returns:
        List of Resource objects.
    """
    resources = []

    for nsg in nsgs:
        resource = Resource(
            resource_type="network_security_group",
            resource_id=nsg.get("id", "unknown"),
            region="global",
            provider="azure",
            config={
                "name": nsg.get("name", ""),
                "inbound_rules": nsg.get("rules", []),
            },
        )
        resources.append(resource)

    return resources


def normalize_azure_resources(
    vms: List[Dict[str, Any]],
    storage_accounts: List[Dict[str, Any]],
    nsgs: List[Dict[str, Any]],
) -> List[Resource]:
    """Normalize all Azure resources into canonical format.

    Args:
        vms: List of VM dictionaries.
        storage_accounts: List of storage account dictionaries.
        nsgs: List of NSG dictionaries.

    Returns:
        List of normalized Resource objects.
    """
    resources = []

    resources.extend(normalize_virtual_machines(vms))
    resources.extend(normalize_storage_accounts(storage_accounts))
    resources.extend(normalize_network_security_groups(nsgs))

    return resources
