from agent.utils import cvss_to_severity
from agent.config_loader import get_config


def compute_risk(findings):
    """
    Compute risk score using formula: Risk = f(Vulnerability Count + CVSS)
    Simplified version for Objectives 1 & 2 (no reachability analysis)

    Returns:
        {
            "max_cvss": float,
            "overall_severity": str,
            "total_vulnerabilities": int,
            "risk_score": float,  # 0-10 scale
        }
    """
    max_cvss = 0.0
    total_vulns = 0

    # Cumulative risk factors
    weighted_cvss_sum = 0.0

    for finding in findings:
        for vuln in finding["vulnerabilities"]:
            total_vulns += 1
            cvss = vuln.get("cvss", 0.0) or 0.0

            weighted_cvss_sum += cvss

            # Track max CVSS overall
            if cvss > max_cvss:
                max_cvss = cvss

    # Calculate composite risk score (0-10 scale)
    # Load weights from configuration
    cfg = get_config()
    weights = cfg.get_risk_weights()
    max_vuln_factor = cfg.get_max_vuln_count_factor()
    multiplier = cfg.get_vuln_count_multiplier()

    # Vulnerability count factor (normalized, capped at max_vuln_factor)
    vuln_count_factor = min(total_vulns * multiplier, max_vuln_factor)

    # CVSS factor (use max CVSS)
    cvss_factor = max_cvss

    # Simplified weighted composite score (no reachability)
    risk_score = (
        (weights['vulnerability_count'] * vuln_count_factor) +
        (weights['cvss_score'] * cvss_factor)
    )
    risk_score = round(risk_score, 2)

    overall_severity = cvss_to_severity(max_cvss)

    return {
        "max_cvss": max_cvss,
        "overall_severity": overall_severity,
        "total_vulnerabilities": total_vulns,
        "risk_score": risk_score
    }