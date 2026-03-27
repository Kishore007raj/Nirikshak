"""
Azure resource normalizer.

Converts raw Azure SDK data into the canonical Resource format
used by the rule engine. Extracts human-readable names from
Azure ARM resource IDs.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.models import Resource


def _extract_name(azure_id: str) -> str:
    """Extract the human-readable resource name from a full Azure ARM resource ID.

    Example:
        /subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/demo123
        -> demo123
    """
    if not azure_id or azure_id == "unknown":
        return "unknown"
    parts = azure_id.strip("/").split("/")
    return parts[-1] if parts else azure_id


def normalize_virtual_machines(
    vms: List[Dict[str, Any]],
) -> List[Resource]:
    """Normalize VM data into Resource objects."""
    resources = []

    for vm in vms:
        raw_id = vm.get("id", "unknown")
        short_name = _extract_name(raw_id)
        display_name = vm.get("name", short_name)

        resource = Resource(
            resource_type="vm",
            resource_id=short_name,
            region=vm.get("location", "unknown"),
            provider="azure",
            config={
                "name": display_name,
                "full_arm_id": raw_id,
                "os_type": vm.get("os_type", "Unknown"),
                "encryption_enabled": vm.get("encryption_enabled", False),
                "public_ip_address": vm.get("public_ip_address", ""),
                "exposed_via_nsg": vm.get("exposed_via_nsg", False),
                "disk_encrypted": vm.get("encryption_enabled", False),
            },
        )
        resources.append(resource)

    return resources


def normalize_storage_accounts(
    accounts: List[Dict[str, Any]],
) -> List[Resource]:
    """Normalize storage account data into Resource objects."""
    resources = []

    for account in accounts:
        raw_id = account.get("id", "unknown")
        short_name = _extract_name(raw_id)
        display_name = account.get("name", short_name)

        resource = Resource(
            resource_type="storage_account",
            resource_id=short_name,
            region=account.get("location", "global"),
            provider="azure",
            config={
                "name": display_name,
                "full_arm_id": raw_id,
                "public_access": account.get("public_access", False),
                "public_write": account.get("public_write", False),
                "encryption": account.get("encryption", False),
                "encryption_enabled": account.get("encryption", False),
                "firewall_enabled": account.get("firewall_enabled", True),
                "min_tls_version": account.get("min_tls_version", 1.2),
                "secure_transfer": account.get("secure_transfer", True),
                "logging_enabled": account.get("logging_enabled", True),
                "versioning_enabled": account.get("versioning_enabled", True),
            },
        )
        resources.append(resource)

    return resources


def normalize_network_security_groups(
    nsgs: List[Dict[str, Any]],
) -> List[Resource]:
    """Normalize NSG data into Resource objects."""
    resources = []

    for nsg in nsgs:
        raw_id = nsg.get("id", "unknown")
        short_name = _extract_name(raw_id)
        display_name = nsg.get("name", short_name)

        resource = Resource(
            resource_type="network_security_group",
            resource_id=short_name,
            region=nsg.get("location", "global"),
            provider="azure",
            config={
                "name": display_name,
                "full_arm_id": raw_id,
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
    """Normalize all Azure resources into canonical format."""
    resources = []

    resources.extend(normalize_virtual_machines(vms))
    resources.extend(normalize_storage_accounts(storage_accounts))
    resources.extend(normalize_network_security_groups(nsgs))

    return resources
