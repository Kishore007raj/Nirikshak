#this file is used to collect the s3 buckets in the AWS account and it will contain all the logic related to collecting the s3 buckets in the AWS account and in the future we will add more functionality to this file as we progress with the development of the application.

import json
from core.models import Resource


def collect_cloudtrail_trails(region, profile):

    with open("demo_data/cloudtrail.json") as f:
        trails = json.load(f)

    resources = []

    for trail in trails:
        resources.append(
            Resource(
                resource_type="cloudtrail",
                resource_id=trail["trail_name"],
                region=region,
                config=trail
            )
        )

    return resources
