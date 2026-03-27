"""
GCP adapter for Nirikshak.

Collects configuration data from Google Cloud
services including compute instances,
storage buckets, and firewall rules.
"""

from __future__ import annotations

from typing import List, Optional

from core.models import Resource


def collect_gcp_resources(region: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect normalized GCP resources.

    Currently only demo mode is supported. This function can be extended to use
    google-cloud SDKs for real scans.
    """
    from utils.helpers import load_demo_data
    
    if mode != "demo":
        # Real GCP scanning not yet implemented.
        return []

    return load_demo_data("gcp")
