import argparse
from agent.sbom_parser import load_sbom, extract_components
from agent.vulnerability_aggregator import aggregate_vulnerabilities, get_vulnerability_summary
from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy
from agent.reporter import generate_markdown_report, save_outputs
from agent.reachability_analyzer import analyze_all_components, enhance_findings_with_reachability


def main():
    parser = argparse.ArgumentParser(
        description="PRISM - Pull-Request Integrated Security Mechanism"
    )
    parser.add_argument("sbom", help="Path to SBOM JSON file")
    parser.add_argument("--rules", help="Path to rules YAML file", default=None)
    parser.add_argument("--output", help="Output directory", default="output")
    parser.add_argument(
        "--sources",
        help="Vulnerability sources to query (comma-separated). Options: osv,github,kev,nvd. Default: osv,github,kev",
        default="osv,github,kev"
    )
    parser.add_argument(
        "--skip-aggregation",
        help="Use only OSV (legacy mode, faster)",
        action="store_true"
    )

    args = parser.parse_args()

    sbom_json = load_sbom(args.sbom)
    components = extract_components(sbom_json)

    # Analyze reachability for all components
    print("🔍 Analyzing component reachability...")
    reachability_data = analyze_all_components(sbom_json)

    findings = []
    
    # Parse sources list
    sources = [s.strip() for s in args.sources.split(",")]

    print(f"\n🔍 Scanning {len(components)} component(s) for vulnerabilities...")
    print(f"   Sources: {', '.join(sources)}\n")

    for comp in components:
        if args.skip_aggregation:
            # Legacy mode - OSV only
            from agent.osv_client import query_osv
            vulns = query_osv(comp["name"], comp["version"], comp.get("ecosystem"))
        else:
            # Multi-feed aggregation
            vulns = aggregate_vulnerabilities(
                comp["name"], 
                comp["version"], 
                comp.get("ecosystem"),
                sources=sources
            )
        
        findings.append({
            "component": comp,
            "vulnerabilities": vulns
        })
        
        print()  # Blank line between components

    # Enhance findings with reachability information
    findings = enhance_findings_with_reachability(findings, reachability_data)

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