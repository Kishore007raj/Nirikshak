#this AWS Adapter file is used to run the AWS scan and it will contain all the logic related to AWS scanning

from aws.collectors.s3 import collect_s3_buckets #for collecting s3 buckets
from aws.collectors.ec2 import collect_ec2_instances #for collecting ec2 instances
from aws.collectors.iam import collect_iam_users #for collecting iam users
from aws.collectors.cloudtrail import collect_cloudtrail_trails #for collecting cloudtrail trails

from core.loader import load_rules #for loading the rules from the rules directory and it will return the rules in a structured format to be used by the rule engine to run the scan and generate the report.
from core.engine import run_engine #for running the rules on the collected resources and it will return the report in a structured format to be used for generating the final report.

from reports.json_report import generate_json_report #for generating the json report from the scan results and it will return the json report in a structured format to be used for saving the report in a file or database and also for sending the report via email or other notification channels.
from reports.csv_report import generate_csv_report #for generating the csv report from the scan results and it will return the csv report in a structured format to be used for saving the report in a file or database and also for sending the report via email or other notification channels.

import uuid
from datetime import datetime

def run_aws_scan(region: str, profile: str):
    
    scan_id = str(uuid.uuid4())
    scan_time = datetime.now().isoformat()

    print("="*60)
    print("NIRIKSHAK - Cloud Misconfiguration Scanner")    
    print("="*60)

    print(f"[NIRIKSHAK] Starting Scan ID: {scan_id} at {scan_time}")
    print(f"[NIRIKSHAK] Region: {region}")
    print(f"[NIRIKSHAK] Profile: {profile}")

    # phase 2 and 3 will call colleectors and rule engine to run the scan and generate the report and in phase 4 we will add the functionality to save the report in a file or database and also add the functionality to send the report via email or other notification channels.  

    resources = []
    resources.extend(collect_s3_buckets(region, profile))
    resources.extend(collect_ec2_instances(region, profile))
    resources.extend(collect_iam_users(region, profile))
    resources.extend(collect_cloudtrail_trails(region, profile))

    print(f"[NIRIKSHAK] Scan completed. Found {len(resources)} resources.\n")
    
    rules = load_rules()
    report = run_engine(resources, rules)

    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for f in report:
        
        severity_count[f['severity']] += 1
    
    risk_score = (
        severity_count["CRITICAL"] * 10 +
        severity_count["HIGH"] * 7 +
        severity_count["MEDIUM"] * 4 +
        severity_count["LOW"] * 1
    )
    
    print("\n=== AWS Scan Report ===")

    for f in report:     
        
        print(f"[{f['severity']}] {f['rule_id']} - {f['title']}")
        print(f"Resource: {f['resource_id']}")
        print(f"Details: {f['details']}")
        print(f"Detected at: {f['detected_at']}\n")
        print(f"CIS Reference: {f.get('cis', 'N/A')}")

    print("=== SUMMARY ===")
    for severity, count in severity_count.items():
        print(f"{severity}: {count}")


    print(f"Risk Score: {risk_score}\n")

    # Generate reports
    generate_json_report(report, severity_count,scan_id, scan_time, risk_score)
    generate_csv_report(report)

    print("\n[NIRIKSHAK] AWS scan report generated.")