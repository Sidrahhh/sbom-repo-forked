import argparse
from agent.sbom_parser import load_sbom, extract_components
from agent.osv_client import query_osv
from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy
from agent.reporter import generate_markdown_report, save_outputs
from agent.remediation_advisor import generate_remediation_summary


def main():
    parser = argparse.ArgumentParser(
        description="PRISM - Pull-Request Integrated Security Mechanism (Objectives 1 & 2)"
    )
    parser.add_argument("sbom", help="Path to SBOM JSON file")
    parser.add_argument("--rules", help="Path to rules YAML file", default=None)
    parser.add_argument("--output", help="Output directory", default="output")
    parser.add_argument(
        "--no-ai",
        help="Disable AI-powered remediation (AI is enabled by default)",
        action="store_true"
    )

    args = parser.parse_args()

    # Check AI configuration
    from agent.config_loader import get_config
    cfg = get_config()
    use_ai = (not args.no_ai) and cfg.is_ai_enabled()

    if use_ai:
        print("🤖 AI-powered smart remediation: ENABLED\n")

    # Load SBOM and extract components
    sbom_json = load_sbom(args.sbom)
    components = extract_components(sbom_json)

    findings = []

    print(f"🔍 Scanning {len(components)} component(s) for vulnerabilities...")
    print(f"   Source: OSV (Open Source Vulnerabilities)\n")

    # Scan each component using OSV
    for comp in components:
        print(f"   🔍 Querying vulnerability databases for {comp.get('name')}@{comp.get('version')}...")
        vulns = query_osv(comp["name"], comp["version"], comp.get("ecosystem"))

        findings.append({
            "component": comp,
            "vulnerabilities": vulns
        })

        print()  # Blank line between components

    risk_summary = compute_risk(findings)

    # Generate remediation advice
    print("\n💊 Generating remediation recommendations...")

    # Use AI remediation by default (unless --no-ai flag is set)
    if use_ai:
        from agent.ai_remediation_advisor import generate_ai_remediation_summary
        remediations = generate_ai_remediation_summary(findings)
    else:
        remediations = generate_remediation_summary(findings)

    rules = load_rules(args.rules) if args.rules else None

    # Use Python-based policy evaluation (OPA removed)
    decision, reason = evaluate_policy(risk_summary, findings, rules)

    markdown = generate_markdown_report(
        risk_summary, findings, decision, reason, remediations, rules=rules
    )

    report_data = {
        "risk_summary": risk_summary,
        "decision": decision,
        "reason": reason,
        "findings": findings,
        "remediations": remediations
    }

    save_outputs(args.output, markdown, report_data)

    print(markdown)


if __name__ == "__main__":
    main()