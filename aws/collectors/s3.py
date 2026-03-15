"""AWS S3 collectors for Nirikshak.

This module supports both demo mode (using local JSON fixtures) and a real scan via boto3.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from core.models import Resource

ROOT_DIR = Path(__file__).resolve().parents[2]


def collect_s3_buckets(region: str, profile: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect S3 bucket configuration data.

    - In demo mode, reads from demo_data/s3.json.
    - In real mode, uses boto3 to query S3 bucket settings.
    """

    if mode == "demo":
        with open(ROOT_DIR / "demo_data" / "s3.json", "r", encoding="utf-8") as f:
            buckets = json.load(f)

        resources: List[Resource] = []
        for bucket in buckets:
            config = {
                "public_access_block": bucket.get("public_access_block", {}),
                "encryption_enabled": bucket.get("encryption_enabled"),
                "versioning_enabled": bucket.get("versioning_enabled"),
            }
            resources.append(
                Resource(
                    resource_type="s3_bucket",
                    resource_id=bucket.get("name"),
                    region=region,
                    provider="aws",
                    config=config,
                )
            )

        return resources

    # Real AWS collection
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise RuntimeError("boto3 is required for real AWS scanning")

    session = boto3.Session(profile_name=profile, region_name=region)
    s3 = session.client("s3")

    resources = []
    try:
        bucket_list = s3.list_buckets().get("Buckets", [])
    except ClientError:
        bucket_list = []

    for bucket in bucket_list:
        bucket_name = bucket.get("Name")
        config: dict = {}

        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
            config["public_access_block"] = pab
        except ClientError:
            config["public_access_block"] = {}

        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)["ServerSideEncryptionConfiguration"]
            config["encryption_enabled"] = True
            config["encryption_details"] = enc
        except ClientError:
            config["encryption_enabled"] = False

        try:
            ver = s3.get_bucket_versioning(Bucket=bucket_name)
            config["versioning_enabled"] = ver.get("Status") == "Enabled"
        except ClientError:
            config["versioning_enabled"] = False

        resources.append(
            Resource(
                resource_type="s3_bucket",
                resource_id=bucket_name,
                region=region,
                provider="aws",
                config=config,
            )
        )

    return resources
