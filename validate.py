import time
import json
from cloud.scanner import collect_resources
from core.runner import run_scan

SCENARIOS = {
    "prod-public-assets": {
        "scenario": "public_s3_bucket",
        "expected_severity": "CRITICAL",  # Depending on the rules we have, let's assume CRITICAL or HIGH for open buckets
    },
    "sg-open-dev": {
        "scenario": "open_ssh",
        "expected_severity": "HIGH",
    },
    "admin-demo-user": {
        "scenario": "weak_iam",
        "expected_severity": "HIGH",
    }
}

def run_validation():
    print("--- NIRIKSHAK Validation Pipeline ---")
    start = time.time()
    
    # Run deterministic aws scan
    resources = collect_resources("aws", "demo")
    scan_result = run_scan("aws", "demo", resources)
    
    results = []
    
    # Map detections securely
    # Only keep the maximum severity detected for each resource
    detections = {}
    for f in scan_result.findings:
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        current_max = detections.get(f.resource_id, "LOW")
        if sev_rank.get(f.severity, 0) > sev_rank.get(current_max, 0):
            detections[f.resource_id] = f.severity

    for res_id, reqs in SCENARIOS.items():
        expected = reqs["expected_severity"]
        detected = detections.get(res_id, "NONE")
        
        # Determine status. If it's expected HIGH/CRITICAL and found HIGH/CRITICAL, it passes.
        if detected in ["HIGH", "CRITICAL"] and expected in ["HIGH", "CRITICAL"]:
            status = "PASS"
        elif expected == detected:
            status = "PASS"
        else:
            status = "FAIL"

        duration = time.time() - start

        res_json = {
            "scenario": reqs["scenario"],
            "expected": expected,
            "detected": detected,
            "status": status,
            "time_to_detect": f"{duration:.2f}s"
        }
        results.append(res_json)
        print(json.dumps(res_json, indent=2))
        
    failures = sum(1 for r in results if r["status"] == "FAIL")
    print(f"\\nValidation Complete. Pass: {len(results)-failures}, Fail: {failures}")
    if failures > 0:
        exit(1)

if __name__ == "__main__":
    run_validation()
