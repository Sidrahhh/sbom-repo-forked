import argparse
from agent.sbom_parser import load_sbom, extract_components
from agent.osv_client import query_osv
from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy
from agent.reporter import generate_markdown_report, save_outputs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", help="Path to SBOM JSON file")
    parser.add_argument("--rules", help="Path to rules YAML file", default=None)
    parser.add_argument("--output", help="Output directory", default="output")

    args = parser.parse_args()

    sbom_json = load_sbom(args.sbom)
    components = extract_components(sbom_json)

    findings = []

    for comp in components:
        vulns = query_osv(comp["name"],comp["version"],comp.get("ecosystem"))
        findings.append({
            "component": comp,
            "vulnerabilities": vulns
        })

    risk_summary = compute_risk(findings)

    rules = load_rules(args.rules) if args.rules else None

    decision, reason = evaluate_policy(risk_summary, findings, rules)

    markdown = generate_markdown_report(
        risk_summary, findings, decision, reason
    )

    report_data = {
        "risk_summary": risk_summary,
        "decision": decision,
        "reason": reason,
        "findings": findings
    }

    save_outputs(args.output, markdown, report_data)

    print(markdown)


if __name__ == "__main__":
    main()