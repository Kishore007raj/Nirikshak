def generate_description(res_type: str, sev: str) -> str:
    return f"{sev.capitalize()} security issue found in {res_type}."

def generate_impact(res_type: str, sev: str) -> str:
    return f"May lead to security vulnerabilities or misconfigurations in {res_type}."

def generate_fix(res_type: str, sev: str) -> str:
    return f"Review and secure the {res_type} configuration according to best practices."
