#this AWS Adapter file is used to run the AWS scan and it will contain all the logic related to AWS scanning

def run_aws_scan(region: str, profile: str):
    print("[NIRIKSHAK] Running AWS scan...")
    print(f"[NIRIKSHAK] AWS Region: {region}")
    print(f"[NIRIKSHAK] AWS Profile: {profile}")

    # phase 2 and 3 will call colleectors and rule engine to run the scan and generate the report and in phase 4 we will add the functionality to save the report in a file or database and also add the functionality to send the report via email or other notification channels.  

    print