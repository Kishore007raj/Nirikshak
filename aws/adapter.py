#this AWS Adapter file is used to run the AWS scan and it will contain all the logic related to AWS scanning

from aws.collectors.s3 import collect_s3_buckets #for collecting s3 buckets
from aws.collectors.ec2 import collect_ec2_instances #for collecting ec2 instances
from aws.collectors.iam import collect_iam_users #for collecting iam users
from aws.collectors.cloudtrail import collect_cloudtrail_trails #for collecting cloudtrail trails

def run_aws_scan(region: str, profile: str):
    print("[NIRIKSHAK] Running AWS scan...")
    print(f"[NIRIKSHAK] AWS Region: {region}")
    print(f"[NIRIKSHAK] AWS Profile: {profile}")

    # phase 2 and 3 will call colleectors and rule engine to run the scan and generate the report and in phase 4 we will add the functionality to save the report in a file or database and also add the functionality to send the report via email or other notification channels.  

    resources = []
    resources.extend(collect_s3_buckets(region, profile))
    resources.extend(collect_ec2_instances(region, profile))
    resources.extend(collect_iam_users(region, profile))
    resources.extend(collect_cloudtrail_trails(region, profile))

    print(f"[NIRIKSHAK] AWS scan completed. Found {len(resources)} resources.")

    