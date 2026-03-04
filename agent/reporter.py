import json
import os


def generate_markdown_report(risk_summary, findings, decision, reason):
    lines = []
    lines.append("## 🔐 PRISM Security Agent Report\n")

    # Decision emoji based on result
    decision_emoji = {
        "PASS": "✅",
        "WARN": "⚠️",
        "FAIL": "❌"
    }.get(decision, "❓")

    lines.append(f"**Decision:** {decision_emoji} {decision}  ")
    lines.append(f"**Overall Severity:** {risk_summary['overall_severity']}  ")
    lines.append(f"**Risk Score:** {risk_summary.get('risk_score', 'N/A')} / 10  ")
    lines.append(f"**Max CVSS:** {risk_summary['max_cvss']} (Reachable: {risk_summary.get('max_reachable_cvss', 'N/A')})  ")
    lines.append(f"**Total Vulnerabilities:** {risk_summary['total_vulnerabilities']} ({risk_summary.get('reachable_vulnerabilities', 0)} reachable, {risk_summary.get('unreachable_vulnerabilities', 0)} unreachable)  \n")

    lines.append("---\n")
    lines.append("### 🚨 Vulnerable Components\n")

    # Track vulnerabilities without CVSS scores and KEV status
    unknown_cvss_count = 0
    kev_count = 0

    for finding in findings:
        if finding["vulnerabilities"]:
            comp = finding["component"]
            reach_info = comp.get("reachability", {})
            reach_status = "✅ Reachable" if reach_info.get("reachable", True) else "🚫 Not Reachable"
            reach_reason = reach_info.get("reason", "Unknown")
            
            lines.append(f"\n#### {comp['name']}@{comp['version']} - {reach_status}")
            lines.append(f"*{reach_reason}*\n")
            
            for vuln in finding["vulnerabilities"]:
                cvss = vuln.get('cvss', 0.0)
                vuln_id = vuln.get('id', 'UNKNOWN')
                
                # Check for CISA KEV status
                kev_status = vuln.get("kev", {})
                is_kev = kev_status.get("in_kev", False)
                
                # Build vulnerability line
                vuln_line = f"- {vuln_id}"
                
                # Add KEV warning
                if is_kev:
                    vuln_line += " 🚨 **ACTIVELY EXPLOITED**"
                    kev_count += 1
                
                # Add CVSS info
                if cvss == 0.0 or cvss is None:
                    vuln_line += " (CVSS: UNKNOWN - manual review needed)"
                    unknown_cvss_count += 1
                else:
                    from agent.utils import cvss_to_severity
                    severity = cvss_to_severity(cvss)
                    vuln_line += f" (CVSS: {cvss}, Severity: {severity})"
                
                # Add source info if from multiple databases
                sources = vuln.get("sources", [vuln.get("source")])
                if isinstance(sources, list) and len(sources) > 1:
                    source_str = ", ".join(sources)
                    vuln_line += f" [Sources: {source_str}]"
                elif sources:
                    source = sources[0] if isinstance(sources, list) else sources
                    vuln_line += f" [Source: {source}]"
                
                lines.append(vuln_line)
                
                # Add KEV details if available
                if is_kev:
                    due_date = kev_status.get("due_date", "")
                    required_action = kev_status.get("required_action", "")
                    if required_action:
                        lines.append(f"  - **Required Action:** {required_action}")
                    if due_date:
                        lines.append(f"  - **CISA Due Date:** {due_date}")

    if not any(f["vulnerabilities"] for f in findings):
        lines.append("\n✅ No vulnerabilities detected.  ")

    # Add warnings
    if kev_count > 0:
        lines.append(f"\n🚨 **CRITICAL WARNING:** {kev_count} vulnerabilities are in CISA's Known Exploited Vulnerabilities catalog - immediate remediation required!  ")
    
    if unknown_cvss_count > 0:
        lines.append(f"\n⚠️ **Note:** {unknown_cvss_count} vulnerabilities have no CVSS score and require manual assessment.  ")

    lines.append("\n---\n")
    lines.append(f"### 🛡️ Policy Decision\n\n{reason}\n")

    return "\n".join(lines)




def save_outputs(output_dir, markdown, json_data):
    import os
    import json

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, "pr_comment.md"), "w", encoding="utf-8") as f:
        f.write(markdown)

    with open(os.path.join(output_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)
