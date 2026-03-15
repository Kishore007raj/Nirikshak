"""GCP adapter stubs for demo mode."""

from __future__ import annotations

from typing import List, Optional

from core.models import Resource


def collect_gcp_resources(region: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect normalized GCP resources.

    Currently only demo mode is supported. This function can be extended to use
    google-cloud SDKs for real scans.
    """

    resources: List[Resource] = []

    if mode != "demo":
        # Real GCP scanning not yet implemented.
        return resources

    resources.append(
        Resource(
            resource_type="gcs_bucket",
            resource_id="demo-gcs-bucket",
            region=region or "global",
            provider="gcp",
            config={
                "public_access_block": {"BlockPublicAcls": False},
                "encryption_enabled": False,
                "versioning_enabled": False,
            },
        )
    )

    resources.append(
        Resource(
            resource_type="compute_instance",
            resource_id="demo-vm",
            region=region or "global",
            provider="gcp",
            config={
                "public_ip_address": "35.35.35.35",
                "disk_encrypted": False,
            },
        )
    )

    return resources
