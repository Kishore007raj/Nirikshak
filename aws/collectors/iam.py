#this file is used to collect the IAM users in the AWS account and it will contain all the logic related to collecting the IAM users in the AWS account and in the future we will add more functionality to this file as we progress with the development of the application.

import json
from core.models import Resource


def collect_iam_users(region, profile):

    with open("demo_data/iam_users.json") as f:
        users = json.load(f)

    resources = []

    for user in users:
        resources.append(
            Resource(
                resource_type="iam_user",
                resource_id=user["user_name"],
                region=region,
                config=user
            )
        )

    return resources
