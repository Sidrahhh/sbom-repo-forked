#!/usr/bin/env python3
"""
Local Testing Script for PRISM Vulnerability Scanner

This script demonstrates the complete workflow locally:
1. Simulates SBOM generation (using pre-made test files)
2. Runs vulnerability scanning
3. Displays results in terminal

Usage:
    python test_local.py [--vulnerable]

Options:
    --vulnerable    Test with a vulnerable SBOM (lodash@4.17.20)
    (default)       Test with a safe SBOM (log4j-core@2.14.1)
"""

import sys
import os
from pathlib import Path

def print_banner():
    """Print test banner"""
    print("\n" + "="*60)
    print("🔐 PRISM LOCAL VULNERABILITY SCAN TEST")
    print("="*60 + "\n")

def run_scan(sbom_path: str, test_name: str):
    """Run vulnerability scan on given SBOM"""
    print(f"📋 Test: {test_name}")
    print(f"📂 SBOM: {sbom_path}")
    print("-" * 60)

    # Import the agent modules
    from agent.sbom_parser import load_sbom, extract_components
    from agent.osv_client import query_osv
    from agent.risk_engine import compute_risk
    from agent.policy_engine import evaluate_policy
    from agent.reporter import generate_markdown_report

    # Run the scanning process
    print("🔍 Step 1: Loading SBOM...")
    sbom_json = load_sbom(sbom_path)
    components = extract_components(sbom_json)
    print(f"   Found {len(components)} component(s)")

    print("\n🔍 Step 2: Scanning for vulnerabilities...")
    findings = []
    for comp in components:
        print(f"   Checking {comp['name']}@{comp['version']}...", end=" ")
        vulns = query_osv(comp["name"], comp["version"], comp.get("ecosystem"))
        findings.append({
            "component": comp,
            "vulnerabilities": vulns
        })
        print(f"{len(vulns)} vulnerabilities found")

    print("\n🔍 Step 3: Computing risk score...")
    risk_summary = compute_risk(findings)
    print(f"   Max CVSS: {risk_summary['max_cvss']}")
    print(f"   Severity: {risk_summary['overall_severity']}")
    print(f"   Total Vulnerabilities: {risk_summary['total_vulnerabilities']}")

    print("\n🔍 Step 4: Evaluating policy...")
    decision, reason = evaluate_policy(risk_summary, findings, rules=None)
    print(f"   Decision: {decision}")
    print(f"   Reason: {reason}")

    print("\n" + "="*60)
    print("📊 FINAL REPORT")
    print("="*60)

    # Generate and display report
    markdown = generate_markdown_report(risk_summary, findings, decision, reason)
    print(markdown)

    print("\n" + "="*60)

    # Return exit code based on decision
    return 0 if decision == "PASS" else 1

def main():
    """Main test function"""
    print_banner()

    # Determine which test to run
    if "--vulnerable" in sys.argv:
        sbom_path = "samples/fail_sbom.json"
        test_name = "Vulnerable Package Test (lodash@4.17.20)"
    else:
        sbom_path = "samples/sample_sbom.json"
        test_name = "Safe Package Test (log4j-core@2.14.1)"

    # Check if file exists
    if not os.path.exists(sbom_path):
        print(f"❌ Error: SBOM file not found: {sbom_path}")
        print("   Make sure you're running this from the repository root.")
        return 1

    # Run the scan
    exit_code = run_scan(sbom_path, test_name)

    print("\n" + "="*60)
    if exit_code == 0:
        print("✅ TEST PASSED - No blocking vulnerabilities")
    else:
        print("❌ TEST FAILED - Blocking vulnerabilities detected")
    print("="*60 + "\n")

    return exit_code

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
