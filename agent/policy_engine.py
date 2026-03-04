import yaml
import re


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


def evaluate_condition(condition: str, context: dict) -> bool:
    """
    Evaluate a simple conditional expression.
    
    Supports:
    - severity == "Critical"
    - reachable == true
    - severity in ["Low", "Medium"]
    - Combined with 'and', 'or'
    
    Args:
        condition: String like 'severity == "Critical" and reachable == true'
        context: Dict with values like {"severity": "CRITICAL", "reachable": True}
    
    Returns:
        bool: True if condition matches
    """
    # Normalize condition
    condition = condition.strip()
    
    # Replace context variables with their values
    # Handle quoted strings
    for key, value in context.items():
        # Convert Python booleans to lowercase for comparison
        if isinstance(value, bool):
            context[key] = str(value).lower()
        elif isinstance(value, str):
            context[key] = value
    
    # Simple pattern matching for common conditions
    # severity == "Critical"
    severity_match = re.search(r'severity\s*==\s*["\'](\w+)["\']', condition)
    if severity_match:
        expected_severity = severity_match.group(1).upper()
        actual_severity = context.get("severity", "UNKNOWN").upper()
        severity_ok = (expected_severity == actual_severity)
    else:
        severity_ok = True  # No severity condition
    
    # reachable == true/false
    reachable_match = re.search(r'reachable\s*==\s*(true|false)', condition, re.IGNORECASE)
    if reachable_match:
        expected_reachable = reachable_match.group(1).lower() == "true"
        actual_reachable = context.get("reachable", True)
        reachable_ok = (expected_reachable == actual_reachable)
    else:
        reachable_ok = True  # No reachability condition
    
    # severity in ["Low", "Medium"]
    severity_in_match = re.search(r'severity\s+in\s+\[(.*?)\]', condition)
    if severity_in_match:
        severity_list = [s.strip(' "\'').upper() for s in severity_in_match.group(1).split(',')]
        actual_severity = context.get("severity", "UNKNOWN").upper()
        severity_in_ok = actual_severity in severity_list
    else:
        severity_in_ok = True
    
    # Combine conditions with 'and'
    if ' and ' in condition.lower():
        return severity_ok and reachable_ok and severity_in_ok
    # Combine with 'or'
    elif ' or ' in condition.lower():
        # For OR, we need to re-evaluate each part
        # This is simplified - a full parser would be better
        return severity_ok or reachable_ok or severity_in_ok
    else:
        return severity_ok and reachable_ok and severity_in_ok


def evaluate_advanced_rules(risk_summary: dict, findings: list, rules: dict) -> tuple:
    """
    Evaluate advanced policy rules with conditional logic.
    
    Rules format:
    rules:
      - type: deny
        when: severity == "Critical" and reachable == true
        msg: "Critical & reachable → Block"
      - type: allow
        when: severity in ["Low", "Medium"]
        msg: "Low/Medium → Allow with warning"
    
    Returns:
        (decision, reason) or (None, None) if no rules match
    """
    if not rules or "rules" not in rules:
        return None, None
    
    rule_list = rules["rules"]
    max_severity = risk_summary.get("overall_severity", "UNKNOWN")
    reachable_vulns = risk_summary.get("reachable_vulnerabilities", 0)
    
    # Build context for condition evaluation
    context = {
        "severity": max_severity,
        "reachable": reachable_vulns > 0,
        "total_vulnerabilities": risk_summary.get("total_vulnerabilities", 0)
    }
    
    for rule in rule_list:
        rule_type = rule.get("type", "").lower()
        when_condition = rule.get("when", "")
        message = rule.get("msg", "Policy rule triggered")
        
        # Evaluate condition
        if evaluate_condition(when_condition, context):
            if rule_type == "deny":
                return "FAIL", message
            elif rule_type == "allow":
                return "PASS", message
            elif rule_type == "warn":
                return "WARN", message
    
    return None, None


def evaluate_policy(risk_summary, findings, rules=None):
    """
    Evaluate security policy based on findings and configured rules.

    Args:
        risk_summary: Risk summary with max_cvss, overall_severity, reachability data
        findings: List of component findings with vulnerabilities
        rules: Optional rules dict from YAML file

    Returns:
        (decision, reason) tuple where decision is PASS/WARN/FAIL
    """
    # Rule 1: blocked package check
    if rules:
        blocked, pkg = check_blocked_packages(findings, rules)
        if blocked:
            return "FAIL", f"Blocked package detected: {pkg}"
    
    # Rule 2: Try advanced conditional rules (new format)
    if rules:
        decision, reason = evaluate_advanced_rules(risk_summary, findings, rules)
        if decision:
            return decision, reason

    # Rule 3: severity gate check (simple format - backward compatible)
    severity = risk_summary["overall_severity"]
    reachable_vulns = risk_summary.get("reachable_vulnerabilities", 0)

    # Get policy gates from rules or use defaults
    if rules and "policy_gates" in rules:
        fail_on = rules["policy_gates"].get("fail_on", ["CRITICAL", "HIGH"])
        warn_on = rules["policy_gates"].get("warn_on", ["MEDIUM"])
        
        # Check if we should only fail on reachable vulnerabilities
        fail_on_reachable_only = rules["policy_gates"].get("fail_on_reachable_only", False)
        
        if fail_on_reachable_only and reachable_vulns == 0:
            return "PASS", "All vulnerabilities are unreachable - safe to proceed"
    else:
        # Default behavior: FAIL on CRITICAL/HIGH, WARN on MEDIUM
        fail_on = ["CRITICAL", "HIGH"]
        warn_on = ["MEDIUM"]

    if severity in fail_on:
        if reachable_vulns > 0:
            return "FAIL", f"Severity threshold exceeded: {severity} vulnerabilities found ({reachable_vulns} reachable)"
        else:
            return "WARN", f"{severity} vulnerabilities found but all are unreachable - review recommended"

    if severity in warn_on:
        return "WARN", f"Warning: {severity} severity vulnerabilities found - review recommended"

    # Check for UNKNOWN severity vulnerabilities (no CVSS score)
    unknown_count = sum(
        1 for f in findings
        for v in f["vulnerabilities"]
        if v.get("cvss", 0) == 0.0
    )

    if unknown_count > 0:
        return "WARN", f"Found {unknown_count} vulnerabilities without CVSS scores - manual review required"

    return "PASS", "No blocking issues"