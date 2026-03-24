"""
AWS adapter for Nirikshak.

Acts as the bridge between the scanner engine
and AWS services using boto3.

Coordinates resource collectors and returns
normalized resource metadata.
"""

from typing import List, Optional

from aws.collectors.cloudtrail import collect_cloudtrail_trails
from aws.collectors.ec2 import collect_security_groups
from aws.collectors.ec2_instances import collect_ec2_instances
from aws.collectors.iam import collect_iam_users
from aws.collectors.s3 import collect_s3_buckets

from core.models import Resource


import logging


def collect_aws_resources(
    region: str,
    profile: Optional[str] = None,
    mode: str = "demo",
) -> List[Resource]:
    """Collect normalized AWS resources for the scan pipeline."""

    logger = logging.getLogger(__name__)

    if mode == "real":
        try:
            resources: List[Resource] = []
            resources.extend(collect_s3_buckets(region, profile, mode))
            resources.extend(collect_security_groups(region, profile, mode))
            resources.extend(collect_ec2_instances(region, profile, mode))
            resources.extend(collect_iam_users(region, profile, mode))
            resources.extend(collect_cloudtrail_trails(region, profile, mode))
            return resources
        except Exception as e:
            # If real AWS collection fails (missing creds, config, etc.), fall back to demo data.
            logger.warning(
                "AWS real collection failed (%s). Falling back to demo data.",
                e,
            )

    # Demo mode or fallback
    from utils.helpers import load_demo_data
    return load_demo_data("aws")
