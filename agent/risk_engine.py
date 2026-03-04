from agent.utils import cvss_to_severity


def compute_risk(findings):
    """
    Compute risk score using formula: Risk = f(Vulnerability Count + CVSS + Reachability)
    
    Returns:
        {
            "max_cvss": float,
            "overall_severity": str,
            "total_vulnerabilities": int,
            "reachable_vulnerabilities": int,
            "unreachable_vulnerabilities": int,
            "risk_score": float,  # 0-10 scale
            "reachability_adjusted_cvss": float
        }
    """
    max_cvss = 0.0
    total_vulns = 0
    reachable_vulns = 0
    unreachable_vulns = 0
    max_reachable_cvss = 0.0
    
    # Cumulative risk factors
    weighted_cvss_sum = 0.0
    
    for finding in findings:
        for vuln in finding["vulnerabilities"]:
            total_vulns += 1
            cvss = vuln.get("cvss", 0.0) or 0.0
            
            # Get reachability score (0.0 = unreachable, 1.0 = definitely reachable)
            reachability_score = vuln.get("reachability_score", 0.5)
            reachability_info = vuln.get("reachability", {})
            is_reachable = reachability_info.get("reachable", True)
            
            # Track reachable vs unreachable
            if is_reachable:
                reachable_vulns += 1
            else:
                unreachable_vulns += 1
            
            # CVSS weighted by reachability
            weighted_cvss = cvss * reachability_score
            weighted_cvss_sum += weighted_cvss
            
            # Track max CVSS overall
            if cvss > max_cvss:
                max_cvss = cvss
            
            # Track max CVSS for reachable vulnerabilities
            if is_reachable and cvss > max_reachable_cvss:
                max_reachable_cvss = cvss

    # Calculate composite risk score (0-10 scale)
    # Formula: Risk = 0.4 * (vuln_count_factor) + 0.5 * (cvss_factor) + 0.1 * (reachability_factor)
    
    # Vulnerability count factor (normalized, capped at 10)
    vuln_count_factor = min(reachable_vulns * 2.0, 10.0)
    
    # CVSS factor (use max reachable CVSS)
    cvss_factor = max_reachable_cvss
    
    # Reachability factor (ratio of reachable to total)
    if total_vulns > 0:
        reachability_factor = (reachable_vulns / total_vulns) * 10.0
    else:
        reachability_factor = 0.0
    
    # Weighted composite score
    risk_score = (0.4 * vuln_count_factor) + (0.5 * cvss_factor) + (0.1 * reachability_factor)
    risk_score = round(risk_score, 2)

    overall_severity = cvss_to_severity(max_reachable_cvss if reachable_vulns > 0 else max_cvss)

    return {
        "max_cvss": max_cvss,
        "max_reachable_cvss": max_reachable_cvss,
        "overall_severity": overall_severity,
        "total_vulnerabilities": total_vulns,
        "reachable_vulnerabilities": reachable_vulns,
        "unreachable_vulnerabilities": unreachable_vulns,
        "risk_score": risk_score,
        "reachability_adjusted_cvss": max_reachable_cvss
    }