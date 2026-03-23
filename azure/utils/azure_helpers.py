"""
Azure helper utilities.

Provides helper functions for Azure Azure credential management, 
resource parsing, and common operations.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient


def get_azure_credential():
    """Get Azure credential using DefaultAzureCredential.

    Returns:
        DefaultAzureCredential instance for Azure SDK operations.
    """
    return DefaultAzureCredential()


def get_compute_client(subscription_id: str) -> ComputeManagementClient:
    """Create and return a ComputeManagementClient instance.

    Args:
        subscription_id: Azure subscription ID.

    Returns:
        ComputeManagementClient instance.
    """
    credential = get_azure_credential()
    return ComputeManagementClient(credential, subscription_id)


def get_storage_client(subscription_id: str) -> StorageManagementClient:
    """Create and return a StorageManagementClient instance.

    Args:
        subscription_id: Azure subscription ID.

    Returns:
        StorageManagementClient instance.
    """
    credential = get_azure_credential()
    return StorageManagementClient(credential, subscription_id)


def get_network_client(subscription_id: str) -> NetworkManagementClient:
    """Create and return a NetworkManagementClient instance.

    Args:
        subscription_id: Azure subscription ID.

    Returns:
        NetworkManagementClient instance.
    """
    credential = get_azure_credential()
    return NetworkManagementClient(credential, subscription_id)


def safe_get(obj: Any, attr: str, default: Any = None) -> Any:
    """Safely get an attribute from an object.

    Args:
        obj: Object to get attribute from.
        attr: Attribute name.
        default: Default value if attribute doesn't exist.

    Returns:
        Attribute value or default.
    """
    try:
        value = getattr(obj, attr, default)
        return value if value is not None else default
    except (AttributeError, TypeError):
        return default


def safe_dict_get(data: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Safely get a key from a dictionary.

    Args:
        data: Dictionary to get key from.
        key: Key name.
        default: Default value if key doesn't exist.

    Returns:
        Key value or default.
    """
    if not isinstance(data, dict):
        return default
    return data.get(key, default)


def extract_os_type(vm_obj: Any) -> str:
    """Extract OS type from a VM object safely.

    Args:
        vm_obj: Azure VM object from ComputeManagementClient.

    Returns:
        OS type string ('Windows', 'Linux', or 'Unknown').
    """
    try:
        os_profile = safe_get(vm_obj, "os_profile")
        if os_profile:
            windows_config = safe_get(os_profile, "windows_config")
            if windows_config:
                return "Windows"
            linux_config = safe_get(os_profile, "linux_config")
            if linux_config:
                return "Linux"
    except Exception:
        pass

    # Fallback to tags
    try:
        tags = safe_get(vm_obj, "tags") or {}
        if isinstance(tags, dict):
            return tags.get("os", "Unknown")
    except Exception:
        pass

    return "Unknown"


def is_encryption_enabled(vm_obj: Any) -> bool:
    """Check if encryption is enabled on a VM.

    Args:
        vm_obj: Azure VM object from ComputeManagementClient.

    Returns:
        True if encryption appears enabled, False otherwise.
    """
    try:
        # Check for disk encryption in storage profile
        storage_profile = safe_get(vm_obj, "storage_profile")
        if storage_profile:
            os_disk = safe_get(storage_profile, "os_disk")
            if os_disk:
                encryption_settings = safe_get(os_disk, "encryption_settings")
                if encryption_settings:
                    enabled = safe_get(encryption_settings, "enabled")
                    return bool(enabled)

        # Check tags for encryption indicators
        tags = safe_get(vm_obj, "tags") or {}
        if isinstance(tags, dict):
            encryption_tag = tags.get("encryption", "").lower()
            if encryption_tag in {"enabled", "true", "yes"}:
                return True

    except Exception:
        pass

    return False


def is_public_access_enabled(storage_obj: Any) -> bool:
    """Check if public access is enabled on a storage account.

    Args:
        storage_obj: Azure storage account object.

    Returns:
        True if public blob access is allowed, False otherwise.
    """
    try:
        allow_blob_public_access = safe_get(
            storage_obj, "allow_blob_public_access"
        )
        return bool(allow_blob_public_access)
    except Exception:
        pass

    return False


def is_blob_encryption_enabled(storage_obj: Any) -> bool:
    """Check if blob encryption is enabled on a storage account.

    Args:
        storage_obj: Azure storage account object.

    Returns:
        True if encryption is enabled, False otherwise.
    """
    try:
        # Try to get encryption from storage account properties
        if hasattr(storage_obj, "encryption"):
            return True
    except Exception:
        pass

    return False


def extract_nsg_rules(nsg_obj: Any) -> list:
    """Extract inbound rules from an NSG object.

    Args:
        nsg_obj: Azure NSG object from NetworkManagementClient.

    Returns:
        List of rule dictionaries with 'port' and 'source' fields.
    """
    rules = []

    try:
        security_rules = safe_get(nsg_obj, "security_rules") or []
        for rule in security_rules:
            if not isinstance(rule, dict):
                # Handle NetworkManagementClient's object type
                rule_dict = {}
                if hasattr(rule, "access"):
                    rule_dict["access"] = rule.access
                if hasattr(rule, "direction"):
                    rule_dict["direction"] = rule.direction
                if hasattr(rule, "destination_port_range"):
                    rule_dict["destination_port_range"] = rule.destination_port_range
                if hasattr(rule, "source_address_prefix"):
                    rule_dict["source_address_prefix"] = rule.source_address_prefix
                rule = rule_dict

            # Only process inbound rules that allow traffic
            if (
                safe_dict_get(rule, "direction", "").lower() == "inbound"
                and safe_dict_get(rule, "access", "").lower() == "allow"
            ):
                port_range = safe_dict_get(
                    rule, "destination_port_range", "*"
                )
                source = safe_dict_get(rule, "source_address_prefix", "*")

                # Parse port range
                if port_range == "*":
                    ports = ["*"]
                elif "-" in str(port_range):
                    try:
                        start, end = port_range.split("-")
                        ports = list(range(int(start), int(end) + 1))
                    except ValueError:
                        ports = [port_range]
                else:
                    try:
                        ports = [int(port_range)]
                    except ValueError:
                        ports = [port_range]

                for port in ports:
                    rules.append(
                        {
                            "port": port,
                            "source": source,
                        }
                    )

    except Exception:
        pass

    return rules
