"""
Configuration loader for Nirikshak.

Loads configuration from settings.yaml including
cloud provider credentials and settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT_DIR / "configs"


def load_config(config_file: str = "settings.yaml") -> Dict[str, Any]:
    """Load configuration from a YAML file.

    Args:
        config_file: Name of the configuration file in the configs directory.

    Returns:
        Dictionary containing configuration settings.
    """
    config_path = CONFIG_DIR / config_file

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        config = {}

    return config


def get_azure_subscription_id() -> str:
    """Get the Azure subscription ID from configuration.

    Returns:
        The Azure subscription ID string.

    Raises:
        ValueError: If subscription ID is not configured.
    """
    config = load_config()

    # Support multiple key formats
    subscription_id = (
        config.get("azure subscription_id")
        or config.get("azure_subscription_id")
        or config.get("subscription_id")
        or config.get("azure", {}).get("subscription_id")
    )

    if not subscription_id:
        raise ValueError(
            "Azure subscription_id not found in settings.yaml. "
            "Please configure 'azure subscription_id' in configs/settings.yaml"
        )

    return str(subscription_id).strip()


def get_aws_credentials() -> Dict[str, str]:
    """Get AWS credentials from configuration.

    Returns:
        Dictionary with AWS credentials.
    """
    config = load_config()
    aws_config = config.get("aws", {})

    return {
        "access_key": aws_config.get("access_key", ""),
        "secret_key": aws_config.get("secret_key", ""),
        "region": aws_config.get("region", "us-east-1"),
        "profile": aws_config.get("profile", ""),
    }


def get_gcp_credentials() -> Dict[str, str]:
    """Get GCP credentials from configuration.

    Returns:
        Dictionary with GCP configuration.
    """
    config = load_config()
    gcp_config = config.get("gcp", {})

    return {
        "project_id": gcp_config.get("project_id", ""),
        "credentials_file": gcp_config.get("credentials_file", ""),
    }
