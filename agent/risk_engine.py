from agent.utils import cvss_to_severity


def compute_risk(findings):
    max_cvss = 0.0
    total_vulns = 0

    for finding in findings:
        for vuln in finding["vulnerabilities"]:
            total_vulns += 1
            if vuln["cvss"] and vuln["cvss"] > max_cvss:
                max_cvss = vuln["cvss"]

    overall_severity = cvss_to_severity(max_cvss)

    return {
        "max_cvss": max_cvss,
        "overall_severity": overall_severity,
        "total_vulnerabilities": total_vulns
    }