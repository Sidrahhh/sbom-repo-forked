import argparse
from agent.sbom_parser import load_sbom, extract_components
from agent.vulnerability_aggregator import aggregate_vulnerabilities, get_vulnerability_summary
from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy
from agent.reporter import generate_markdown_report, save_outputs
from agent.reachability_analyzer import analyze_all_components, enhance_findings_with_reachability
from agent.remediation_advisor import generate_remediation_summary


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
    parser.add_argument(
        "--no-ai",
        help="Disable AI-powered remediation (AI is enabled by default)",
        action="store_true"
    )
    parser.add_argument(
        "--multi-agent",
        help="Enable multi-agent analysis system (advanced mode)",
        action="store_true"
    )
    parser.add_argument(
        "--project-root",
        help="Path to project root for code analysis and reachability detection",
        default=None
    )

    args = parser.parse_args()

    # Check AI configuration
    from agent.config_loader import get_config
    cfg = get_config()
    use_ai = (not args.no_ai) and cfg.is_ai_enabled()

    if use_ai:
        print("🤖 AI-powered smart remediation: ENABLED\n")

    if args.multi_agent:
        print("✅ Multi-agent analysis enabled (--multi-agent flag)\n")

    # If multi-agent mode is enabled, use the orchestrator
    if args.multi_agent:
        from agent.multi_agent_orchestrator import MultiAgentOrchestrator
        orchestrator = MultiAgentOrchestrator(
            project_root=args.project_root,
            enable_ai=use_ai,
            enable_opa=False  # OPA removed
        )

        print("🧠 Running multi-agent analysis...\n")
        result = orchestrator.analyze_sbom(args.sbom)

        # Save outputs
        save_outputs(args.output, result['report_markdown'], result)
        print(result['report_markdown'])
        return

    # Standard single-agent mode
    sbom_json = load_sbom(args.sbom)
    components = extract_components(sbom_json)

    # Analyze reachability for all components
    print("🔍 Analyzing component reachability...")
    if args.project_root:
        print(f"   Project root: {args.project_root}")
        print("   Level 2 (code-based) analysis: ENABLED")
    else:
        print("   Level 1 (metadata-based) analysis only")

    reachability_data = analyze_all_components(
        sbom_json,
        project_root=args.project_root,
        enable_level_2=(args.project_root is not None)
    )

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

    # Generate remediation advice
    print("\n💊 Generating remediation recommendations...")

    # Use AI remediation by default (unless --no-ai flag is set)
    if use_ai:
        from agent.ai_remediation_advisor import generate_ai_remediation_summary
        remediations = generate_ai_remediation_summary(
            findings,
            project_root=args.project_root
        )
    else:
        remediations = generate_remediation_summary(findings)

    rules = load_rules(args.rules) if args.rules else None

    # Use Python-based policy evaluation (OPA removed)
    decision, reason = evaluate_policy(risk_summary, findings, rules)

    markdown = generate_markdown_report(
        risk_summary, findings, decision, reason, remediations
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