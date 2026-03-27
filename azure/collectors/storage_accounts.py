"""
Azure Storage Accounts collector.

Fetches details of all storage accounts in an Azure subscription
using StorageManagementClient.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from azure.core.exceptions import AzureError


def collect_storage_accounts(
    subscription_id: str,
) -> List[Dict[str, Any]]:
    """Collect all storage accounts from the Azure subscription.

    Args:
        subscription_id: Azure subscription ID.

    Returns:
        List of storage account dictionaries with name, public_access, and encryption.
    """
    from azure.utils.azure_helpers import (
        is_blob_encryption_enabled,
        is_public_access_enabled,
        safe_get,
        get_storage_client,
    )

    storage_accounts = []

    try:
        client = get_storage_client(subscription_id)

        # List all storage accounts
        for account in client.storage_accounts.list():
            try:
                account_data = {
                    "id": safe_get(account, "id", "unknown"),
                    "name": safe_get(account, "name", "unknown"),
                    "public_access": is_public_access_enabled(account),
                    "encryption": is_blob_encryption_enabled(account),
                }
                storage_accounts.append(account_data)

            except Exception as e:
                # Skip accounts with collection errors
                print(f"Warning: Failed to collect storage account details: {e}")
                continue

    except AzureError as e:
        print(f"Error collecting storage accounts: {e}")
    except Exception as e:
        print(f"Unexpected error collecting storage accounts: {e}")

    return storage_accounts
