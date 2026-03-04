import json
import os


def generate_markdown_report(risk_summary, findings, decision, reason):
    lines = []
    lines.append("## 🔐 Safe PR Agent Report\n")
    lines.append(f"**Decision:** {'❌ FAIL' if decision == 'FAIL' else '✅ PASS'}  ")
    lines.append(f"**Overall Severity:** {risk_summary['overall_severity']}  ")
    lines.append(f"**Max CVSS:** {risk_summary['max_cvss']}  ")
    lines.append(f"**Total Vulnerabilities:** {risk_summary['total_vulnerabilities']}  \n")

    lines.append("---\n")
    lines.append("### 🚨 Vulnerable Components\n")

    for finding in findings:
        if finding["vulnerabilities"]:
            comp = finding["component"]
            lines.append(f"- {comp['name']}@{comp['version']}")
            for vuln in finding["vulnerabilities"]:
                lines.append(f"  - {vuln['id']} (CVSS: {vuln['cvss']})")

    lines.append("\n---\n")
    lines.append(f"### 🛡️ Policy Result\n{reason}\n")

    return "\n".join(lines)




def save_outputs(output_dir, markdown, json_data):
    import os
    import json

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, "pr_comment.md"), "w", encoding="utf-8") as f:
        f.write(markdown)

    with open(os.path.join(output_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)