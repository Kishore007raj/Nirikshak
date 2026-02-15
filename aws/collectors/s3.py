#this file is used to collect the s3 buckets in the AWS account and it will contain all the logic related to collecting the s3 buckets in the AWS account and in the future we will add more functionality to this file as we progress with the development of the application.

import json
from core.models import Resource


def collect_s3_buckets(region, profile):

    with open("demo_data/s3.json") as f:
        buckets = json.load(f)

    resources = []

    for bucket in buckets:
        config = {
            "public_access_block": bucket["public_access_block"],
            "encryption_enabled": bucket["encryption_enabled"]
        }

        resources.append(
            Resource(
                resource_type="s3_bucket",
                resource_id=bucket["name"],
                region=region,
                config=config
            )
        )

    return resources
