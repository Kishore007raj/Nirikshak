import csv


def generate_csv_report(findings):

    with open("nirikshak_report.csv", "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "Rule ID",
            "Title",
            "Severity",
            "CIS",
            "Resource Type",
            "Resource ID"
        ])

        for fnd in findings:
            writer.writerow([
                fnd["rule_id"],
                fnd["title"],
                fnd["severity"],
                fnd["cis"],
                fnd["resource_type"],
                fnd["resource_id"]
            ])

    print("CSV report generated: nirikshak_report.csv")
