import yaml


def load_rules(rules_path):
    try:
        with open(rules_path, "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def check_blocked_packages(findings, rules):
    if not rules:
        return False, None

    blocked = rules.get("blocked_packages", [])

    for finding in findings:
        name = finding["component"]["name"]
        if name in blocked:
            return True, name

    return False, None


def evaluate_policy(risk_summary, findings, rules=None):
    # Rule 1: blocked package
    if rules:
        blocked, pkg = check_blocked_packages(findings, rules)
        if blocked:
            return "FAIL", f"Blocked package detected: {pkg}"

    # Rule 2: severity gate
    if risk_summary["overall_severity"] in ["CRITICAL", "HIGH"]:
        return "FAIL", "Severity threshold exceeded"

    return "PASS", "No blocking issues"