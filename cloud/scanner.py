"""
Cloud scanning orchestrator.

Determines which cloud provider to scan
and invokes the appropriate adapter.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.models import Resource

from aws.adapter import collect_aws_resources


def collect_resources(provider: str, mode: str = "demo", **kwargs: Any) -> List[Resource]:
    """Collect normalized resources for a given provider and mode."""

    logger = logging.getLogger(__name__)
    provider = provider.lower().strip()

    if provider == "aws":
        return collect_aws_resources(kwargs.get("region", ""), kwargs.get("profile"), mode)

    if provider == "azure":
        from azure.adapter import collect_azure_resources

        if mode == "real":
            logger.debug("Collecting live Azure resources")
        else:
            logger.debug("Using Azure demo resources")
        return collect_azure_resources(mode=mode)

    if provider == "gcp":
        from gcp.adapter import collect_gcp_resources

        logger.debug("Using GCP demo resources")
        return collect_gcp_resources(mode=mode)

    raise ValueError(f"Unsupported provider: {provider}")
