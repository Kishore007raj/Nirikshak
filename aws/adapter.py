#this AWS Adapter file is used to run the AWS scan and it will contain all the logic related to AWS scanning

from aws.collectors.s3 import collect_s3_buckets #for collecting s3 buckets
from aws.collectors.ec2 import collect_ec2_instances #for collecting ec2 instances
from aws.collectors.iam import collect_iam_users #for collecting iam users
from aws.collectors.cloudtrail import collect_cloudtrail_trails #for collecting cloudtrail trails
from core.loader import load_rules #for loading the rules from the rules directory and it will return the rules in a structured format to be used by the rule engine to run the scan and generate the report.
from core.engine import run_engine #for running the rules on the collected resources and it will return the report in a structured format to be used for generating the final report.

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

    rules = load_rules()
    report = run_engine(resources, rules)

    print("\n=== AWS Scan Report ===")

    for f in report:
        print(f"\nRule ID: {f['rule_id']}")
        print(f"Title: {f['title']}")
        print(f"Severity: {f['severity']}")
        print(f"Resource ID: {f['resource_id']}")
        print(f"Resource Type: {f['resource_type']}")
        print(f"Region: {f['region']}")
        print(f"Details: {f['details']}")

    print("\n[NIRIKSHAK] AWS scan report generated.")