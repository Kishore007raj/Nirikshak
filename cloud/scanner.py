"""Cloud provider scanning orchestration.

The scanner abstracts cloud-specific collection logic and ensures every provider
returns a normalized set of resources that the rest of the pipeline can process.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.models import Resource

from aws.adapter import collect_aws_resources


def collect_resources(provider: str, mode: str = "demo", **kwargs: Any) -> List[Resource]:
    """Collect normalized resources for a given provider and mode."""

    provider = provider.lower().strip()
    if provider == "aws":
        return collect_aws_resources(kwargs.get("region", ""), kwargs.get("profile"), mode)

    # Placeholder implementations for providers not yet fully implemented.
    # These can be expanded with real SDK integrations later.
    if provider == "azure":
        # Azure support is currently demo-only.
        from azure.adapter import collect_azure_resources

        return collect_azure_resources(mode=mode)

    if provider == "gcp":
        from gcp.adapter import collect_gcp_resources

        return collect_gcp_resources(mode=mode)

    raise ValueError(f"Unsupported provider: {provider}")
