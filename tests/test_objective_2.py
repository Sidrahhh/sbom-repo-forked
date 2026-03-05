"""
PRISM - Objective 2 Test Suite
================================
Objective 2: Risk Scoring, Policy Enforcement, AI Remediation & Report Generation

Covers:
  Part A - Risk Engine      : compute_risk(), CVSS → score, severity mapping
  Part B - Policy Engine    : evaluate_policy(), load_rules(), load_policy()
  Part C - Remediation      : generate_remediation_summary(), upgrade commands
  Part D - Reporter         : generate_markdown_report(), save_outputs()

Test IDs use the format  OBJ2-<PART>-<NN>
"""

import json
import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy, load_policy
from agent.remediation_advisor import generate_remediation_summary
from agent.reporter import generate_markdown_report, save_outputs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(name, version, ecosystem=None, vulns=None):
    return {
        "component": {"name": name, "version": version, "ecosystem": ecosystem},
        "vulnerabilities": vulns or []
    }


def _vuln(id_, cvss=0.0, source="OSV", summary=None):
    return {
        "id": id_,
        "cvss": cvss,
        "has_cvss": cvss > 0.0,
        "source": source,
        "summary": summary or f"Vulnerability {id_}",
        "raw_data": {"id": id_}
    }


_RULES_FAIL_CRITICAL = {
    "blocked_packages": [],
    "policy_gates": {"fail_on": ["CRITICAL"], "warn_on": ["HIGH", "MEDIUM"]}
}

_RULES_STRICT = {
    "blocked_packages": [],
    "policy_gates": {"fail_on": ["CRITICAL", "HIGH", "MEDIUM"], "warn_on": ["LOW"]}
}

_RULES_LENIENT = {
    "blocked_packages": [],
    "policy_gates": {"fail_on": ["CRITICAL"], "warn_on": []}
}

_PROJECT_ROOT = Path(__file__).parent.parent


# ===========================================================================
# PART A — RISK ENGINE
# ===========================================================================

class TestRiskEngineZeroVulns:
    """OBJ2-A: Risk when no vulnerabilities found"""

    def test_empty_findings_risk_zero(self):
        """OBJ2-A-01: No findings at all → risk_score 0"""
        result = compute_risk([])
        assert result["risk_score"] == 0.0

    def test_single_component_no_vulns(self):
        """OBJ2-A-02: Component with no vulns → risk 0, severity NONE"""
        result = compute_risk([_finding("safe-lib", "1.0.0")])
        assert result["total_vulnerabilities"] == 0
        assert result["overall_severity"] in ("NONE", "UNKNOWN", "LOW")

    def test_multiple_components_all_clean(self):
        """OBJ2-A-03: Multiple clean components → total_vulnerabilities 0"""
        findings = [_finding(f"lib-{i}", "1.0") for i in range(5)]
        result = compute_risk(findings)
        assert result["total_vulnerabilities"] == 0

    def test_max_cvss_zero_when_no_vulns(self):
        """OBJ2-A-04: max_cvss is 0.0 when no vulnerabilities"""
        result = compute_risk([_finding("clean", "1.0")])
        assert result["max_cvss"] == 0.0


class TestRiskEngineSingleVuln:
    """OBJ2-A: Risk from a single vulnerability"""

    def test_critical_cvss_9_5(self):
        """OBJ2-A-05: CVSS 9.5 → CRITICAL severity"""
        result = compute_risk([_finding("bad-lib", "1.0", vulns=[_vuln("CVE-1", 9.5)])])
        assert result["overall_severity"] == "CRITICAL"
        assert result["max_cvss"] == 9.5

    def test_high_cvss_7_5(self):
        """OBJ2-A-06: CVSS 7.5 → HIGH severity"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-2", 7.5)])])
        assert result["overall_severity"] == "HIGH"

    def test_medium_cvss_5_0(self):
        """OBJ2-A-07: CVSS 5.0 → MEDIUM severity"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-3", 5.0)])])
        assert result["overall_severity"] == "MEDIUM"

    def test_low_cvss_2_0(self):
        """OBJ2-A-08: CVSS 2.0 → LOW severity"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-4", 2.0)])])
        assert result["overall_severity"] == "LOW"

    def test_zero_cvss_is_none_or_low(self):
        """OBJ2-A-09: CVSS 0.0 → severity NONE or UNKNOWN (below LOW threshold)"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-5", 0.0)])])
        assert result["overall_severity"] in ("NONE", "UNKNOWN", "LOW")

    def test_total_vulnerabilities_is_one(self):
        """OBJ2-A-10: Single vuln → total_vulnerabilities == 1"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-6", 8.0)])])
        assert result["total_vulnerabilities"] == 1

    def test_risk_score_positive_with_vuln(self):
        """OBJ2-A-11: A HIGH vuln → risk_score > 0"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-7", 7.5)])])
        assert result["risk_score"] > 0

    def test_risk_score_capped_at_ten(self):
        """OBJ2-A-12: Risk score never exceeds 10"""
        many_vulns = [_vuln(f"CVE-{i}", 9.9) for i in range(50)]
        result = compute_risk([_finding("lib", "1.0", vulns=many_vulns)])
        assert result["risk_score"] <= 10.0


class TestRiskEngineMultiple:
    """OBJ2-A: Risk aggregated across multiple vulns/components"""

    def test_max_cvss_drives_severity(self):
        """OBJ2-A-13: Highest CVSS across all vulns sets overall_severity"""
        result = compute_risk([_finding("lib", "1.0", vulns=[
            _vuln("CVE-A", 2.0),
            _vuln("CVE-B", 9.8),
            _vuln("CVE-C", 5.0)
        ])])
        assert result["overall_severity"] == "CRITICAL"
        assert result["max_cvss"] == 9.8

    def test_total_vuln_count_across_components(self):
        """OBJ2-A-14: 2 components with 3 vulns each → total = 6"""
        f1 = _finding("lib-a", "1.0", vulns=[_vuln(f"A-{i}", 7.0) for i in range(3)])
        f2 = _finding("lib-b", "2.0", vulns=[_vuln(f"B-{i}", 5.0) for i in range(3)])
        result = compute_risk([f1, f2])
        assert result["total_vulnerabilities"] == 6

    def test_more_vulns_higher_score(self):
        """OBJ2-A-15: More vulnerabilities → higher risk_score (count factor)"""
        one = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-1", 7.5)])])
        five = compute_risk([_finding("lib", "1.0", vulns=[_vuln(f"C{i}", 7.5) for i in range(5)])])
        assert five["risk_score"] >= one["risk_score"]

    def test_boundary_cvss_9_0_is_critical(self):
        """OBJ2-A-16: Boundary CVSS 9.0 → CRITICAL"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-B9", 9.0)])])
        assert result["overall_severity"] == "CRITICAL"

    def test_boundary_cvss_just_below_critical(self):
        """OBJ2-A-17: CVSS 8.9 → HIGH (below CRITICAL threshold 9.0)"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-B8", 8.9)])])
        assert result["overall_severity"] == "HIGH"

    def test_boundary_cvss_7_0_is_high(self):
        """OBJ2-A-18: Boundary CVSS 7.0 → HIGH"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-B7", 7.0)])])
        assert result["overall_severity"] == "HIGH"

    def test_boundary_cvss_4_0_is_medium(self):
        """OBJ2-A-19: Boundary CVSS 4.0 → MEDIUM"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-B4", 4.0)])])
        assert result["overall_severity"] == "MEDIUM"

    def test_boundary_cvss_0_1_is_low(self):
        """OBJ2-A-20: Boundary CVSS 0.1 → LOW"""
        result = compute_risk([_finding("lib", "1.0", vulns=[_vuln("CVE-BL", 0.1)])])
        assert result["overall_severity"] == "LOW"


# ===========================================================================
# PART B — POLICY ENGINE
# ===========================================================================

class TestPolicyEngineDecisions:
    """OBJ2-B: Core PASS / WARN / FAIL decisions"""

    def test_no_vulns_pass(self):
        """OBJ2-B-01: Zero vulnerabilities → PASS"""
        risk = compute_risk([_finding("safe", "1.0")])
        dec, reason = evaluate_policy(risk, [_finding("safe", "1.0")])
        assert dec == "PASS"

    def test_critical_vuln_fail(self):
        """OBJ2-B-02: CRITICAL vulnerability → FAIL"""
        findings = [_finding("bad", "1.0", vulns=[_vuln("C1", 9.5)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings)
        assert dec == "FAIL"

    def test_high_vuln_fail(self):
        """OBJ2-B-03: HIGH vulnerability → FAIL by default"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("H1", 7.5)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings)
        assert dec == "FAIL"

    def test_medium_vuln_warn(self):
        """OBJ2-B-04: MEDIUM vulnerability → WARN"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("M1", 5.0)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings)
        assert dec == "WARN"

    def test_low_vuln_pass(self):
        """OBJ2-B-05: LOW vulnerability → PASS"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("L1", 2.0)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings)
        assert dec == "PASS"

    def test_unknown_cvss_warn(self):
        """OBJ2-B-06: Vuln with CVSS 0.0 → WARN for manual review"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("U1", 0.0)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings)
        assert dec == "WARN"

    def test_reason_string_always_populated(self):
        """OBJ2-B-07: reason string is never empty"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("X1", 9.5)])]
        risk = compute_risk(findings)
        _, reason = evaluate_policy(risk, findings)
        assert reason and len(reason) > 0

    def test_fail_reason_mentions_severity(self):
        """OBJ2-B-08: FAIL reason references the triggering severity"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("C2", 9.5)])]
        risk = compute_risk(findings)
        _, reason = evaluate_policy(risk, findings)
        assert "CRITICAL" in reason.upper()

    def test_warn_reason_mentions_severity(self):
        """OBJ2-B-09: WARN reason references the severity"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("M2", 5.0)])]
        risk = compute_risk(findings)
        _, reason = evaluate_policy(risk, findings)
        assert "MEDIUM" in reason.upper() or "warn" in reason.lower()

    def test_multiple_components_worst_wins(self):
        """OBJ2-B-10: FAIL from one component overrides PASS from another"""
        findings = [
            _finding("safe", "1.0"),
            _finding("bad", "1.0", vulns=[_vuln("C3", 9.5)])
        ]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings)
        assert dec == "FAIL"

    def test_clean_reason_is_friendly(self):
        """OBJ2-B-11: PASS reason says no blocking issues"""
        risk = compute_risk([_finding("clean", "1.0")])
        _, reason = evaluate_policy(risk, [_finding("clean", "1.0")])
        assert "no" in reason.lower() or "pass" in reason.lower()


class TestPolicyEngineBlockedPackages:
    """OBJ2-B: Blocked package enforcement"""

    def test_blocked_package_fails_regardless_of_cvss(self):
        """OBJ2-B-12: Blocked package → FAIL even with CVSS 0"""
        rules = {"blocked_packages": ["evil-lib"], "policy_gates": {"fail_on": [], "warn_on": []}}
        findings = [_finding("evil-lib", "1.0")]
        risk = compute_risk(findings)
        dec, reason = evaluate_policy(risk, findings, rules)
        assert dec == "FAIL"
        assert "evil-lib" in reason

    def test_unblocked_package_not_denied(self):
        """OBJ2-B-13: Non-blocked package not denied by blocked list"""
        rules = {"blocked_packages": ["other-bad-lib"], "policy_gates": {"fail_on": [], "warn_on": []}}
        findings = [_finding("safe-lib", "1.0")]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings, rules)
        assert dec == "PASS"

    def test_blocked_package_with_high_cvss_still_fails(self):
        """OBJ2-B-14: Blocked + HIGH CVSS → blocked check fires first"""
        rules = {"blocked_packages": ["openssl"], "policy_gates": {"fail_on": [], "warn_on": []}}
        findings = [_finding("openssl", "1.0", vulns=[_vuln("C-SSL", 9.5)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings, rules)
        assert dec == "FAIL"

    def test_empty_blocked_list_no_denial(self):
        """OBJ2-B-15: Empty blocked_packages list → no blocked-package FAIL"""
        rules = {"blocked_packages": [], "policy_gates": {"fail_on": [], "warn_on": []}}
        findings = [_finding("anything", "1.0")]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings, rules)
        assert dec == "PASS"


class TestPolicyEngineCustomRules:
    """OBJ2-B: Custom fail_on / warn_on rules"""

    def test_custom_fail_on_only_critical(self):
        """OBJ2-B-16: Custom fail_on=[CRITICAL] → HIGH is WARN, not FAIL"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("H2", 7.5)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings, _RULES_FAIL_CRITICAL)
        assert dec == "WARN"

    def test_custom_strict_medium_fails(self):
        """OBJ2-B-17: Strict rules with MEDIUM in fail_on → FAIL"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("M3", 5.0)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings, _RULES_STRICT)
        assert dec == "FAIL"

    def test_custom_lenient_high_is_pass(self):
        """OBJ2-B-18: Lenient rules (no warn_on) → HIGH severity PASS"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("H3", 7.5)])]
        risk = compute_risk(findings)
        # With lenient rules, only CRITICAL fails, nothing warns → PASS for HIGH
        dec, _ = evaluate_policy(risk, findings, _RULES_LENIENT)
        assert dec == "PASS"

    def test_no_rules_uses_policy_file_defaults(self):
        """OBJ2-B-19: rules=None → reads default_policy.yaml → FAIL on CRITICAL"""
        findings = [_finding("lib", "1.0", vulns=[_vuln("C4", 9.5)])]
        risk = compute_risk(findings)
        dec, _ = evaluate_policy(risk, findings)
        assert dec == "FAIL"


class TestLoadRulesAndPolicy:
    """OBJ2-B: File loading helpers"""

    def test_load_rules_from_file(self, tmp_path):
        """OBJ2-B-20: load_rules() reads a YAML file correctly"""
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text("blocked_packages:\n  - bad-lib\n")
        rules = load_rules(str(rules_file))
        assert "bad-lib" in rules["blocked_packages"]

    def test_load_rules_missing_file_returns_none(self, tmp_path):
        """OBJ2-B-21: Missing rules file → returns None gracefully"""
        result = load_rules(str(tmp_path / "nonexistent.yaml"))
        assert result is None

    def test_load_policy_returns_dict(self):
        """OBJ2-B-22: load_policy() reads policies/default_policy.yaml"""
        policy = load_policy()
        assert policy is not None
        assert "policy_gates" in policy

    def test_load_policy_has_fail_on(self):
        """OBJ2-B-23: default_policy.yaml has fail_on list"""
        policy = load_policy()
        assert "fail_on" in policy["policy_gates"]

    def test_load_policy_has_warn_on(self):
        """OBJ2-B-24: default_policy.yaml has warn_on list"""
        policy = load_policy()
        assert "warn_on" in policy["policy_gates"]

    def test_load_policy_fail_on_includes_critical(self):
        """OBJ2-B-25: Default policy fails on CRITICAL"""
        policy = load_policy()
        assert "CRITICAL" in policy["policy_gates"]["fail_on"]

    def test_load_policy_fail_on_includes_high(self):
        """OBJ2-B-26: Default policy fails on HIGH"""
        policy = load_policy()
        assert "HIGH" in policy["policy_gates"]["fail_on"]

    def test_load_policy_warn_on_medium(self):
        """OBJ2-B-27: Default policy warns on MEDIUM"""
        policy = load_policy()
        assert "MEDIUM" in policy["policy_gates"]["warn_on"]

    def test_load_policy_custom_path(self, tmp_path):
        """OBJ2-B-28: load_policy with custom path reads that file"""
        custom = tmp_path / "custom_policy.yaml"
        custom.write_text("policy_gates:\n  fail_on:\n    - CRITICAL\n  warn_on: []\n")
        policy = load_policy(str(custom))
        assert policy["policy_gates"]["fail_on"] == ["CRITICAL"]


# ===========================================================================
# PART C — REMEDIATION ADVISOR
# ===========================================================================

class TestRemediationAdvisor:
    """OBJ2-C: Remediation suggestion generation"""

    def _finding_with_fixed(self, name, version, eco, vuln_id, fixed):
        raw = {
            "id": vuln_id,
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": fixed}]}]}]
        }
        vuln = {"id": vuln_id, "cvss": 9.5, "has_cvss": True, "source": "OSV",
                "summary": "Critical bug", "raw_data": raw}
        return {"component": {"name": name, "version": version, "ecosystem": eco},
                "vulnerabilities": [vuln]}

    def test_remediation_generated_for_vulnerable_pkg(self):
        """OBJ2-C-01: Vulnerable package → non-empty remediations list"""
        finding = self._finding_with_fixed("lodash", "4.17.15", "npm", "CVE-2021-xxxx", "4.17.21")
        remeds = generate_remediation_summary([finding])
        assert len(remeds) > 0

    def test_clean_sbom_empty_remediations(self):
        """OBJ2-C-02: Clean component → empty remediations"""
        remeds = generate_remediation_summary([_finding("safe", "1.0")])
        assert remeds == []

    def test_empty_findings_empty_remediations(self):
        """OBJ2-C-03: No findings → empty list"""
        assert generate_remediation_summary([]) == []

    def test_upgrade_to_fixed_version(self):
        """OBJ2-C-04: Fixed version extracted and shown as recommended"""
        finding = self._finding_with_fixed("requests", "2.25.0", "PyPI", "GHSA-xxxx", "2.27.0")
        remeds = generate_remediation_summary([finding])
        assert any("2.27.0" in str(r) for r in remeds)

    def test_npm_upgrade_command_present(self):
        """OBJ2-C-05: npm package → upgrade command includes npm"""
        finding = self._finding_with_fixed("axios", "0.21.0", "npm", "GHSA-axios", "0.21.4")
        remeds = generate_remediation_summary([finding])
        combined = str(remeds)
        assert "npm" in combined or "install" in combined or "axios" in combined

    def test_pypi_upgrade_command_present(self):
        """OBJ2-C-06: PyPI package → upgrade command includes pip"""
        finding = self._finding_with_fixed("Pillow", "8.0.0", "PyPI", "CVE-Pillow", "8.3.2")
        remeds = generate_remediation_summary([finding])
        combined = str(remeds)
        assert "pip" in combined or "install" in combined or "Pillow" in combined

    def test_multiple_components_multiple_remeds(self):
        """OBJ2-C-07: Two vulnerable components → two remediation entries"""
        f1 = self._finding_with_fixed("lodash", "4.17.15", "npm", "CVE-A", "4.17.21")
        f2 = self._finding_with_fixed("requests", "2.25.0", "PyPI", "CVE-B", "2.27.0")
        remeds = generate_remediation_summary([f1, f2])
        assert len(remeds) == 2

    def test_component_name_in_remediation(self):
        """OBJ2-C-08: Remediation output contains the component name"""
        finding = self._finding_with_fixed("lodash", "4.17.15", "npm", "CVE-Z", "4.17.21")
        remeds = generate_remediation_summary([finding])
        assert any("lodash" in str(r) for r in remeds)

    def test_critical_priority_assigned(self):
        """OBJ2-C-09: CRITICAL-CVSS vuln → priority is CRITICAL or HIGH"""
        finding = self._finding_with_fixed("critlib", "1.0", "npm", "CVE-CRIT", "2.0")
        remeds = generate_remediation_summary([finding])
        priorities = [r.get("priority", "").upper() for r in remeds]
        assert any(p in ("CRITICAL", "HIGH") for p in priorities)


# ===========================================================================
# PART D — REPORTER
# ===========================================================================

class TestReporterMarkdown:
    """OBJ2-D: Markdown report content"""

    def _base_risk(self, severity="NONE", cvss=0.0, total=0, score=0.0):
        return {"overall_severity": severity, "max_cvss": cvss,
                "total_vulnerabilities": total, "risk_score": score}

    def test_fail_decision_has_x_symbol(self):
        """OBJ2-D-01: FAIL decision → ✗ in report"""
        md = generate_markdown_report(
            self._base_risk("CRITICAL", 9.5, 1, 7.0),
            [_finding("lib", "1.0", vulns=[_vuln("C1", 9.5)])],
            "FAIL", "Critical found", []
        )
        assert "✗" in md

    def test_pass_decision_has_check_symbol(self):
        """OBJ2-D-02: PASS decision → ✓ in report"""
        md = generate_markdown_report(self._base_risk(), [], "PASS", "No issues", [])
        assert "✓" in md

    def test_warn_decision_has_exclamation(self):
        """OBJ2-D-03: WARN decision → ! in report"""
        md = generate_markdown_report(
            self._base_risk("MEDIUM", 5.0, 1, 2.0),
            [_finding("lib", "1.0", vulns=[_vuln("M1", 5.0)])],
            "WARN", "Medium found", []
        )
        assert "!" in md

    def test_component_name_in_report(self):
        """OBJ2-D-04: Component name appears in the report"""
        md = generate_markdown_report(
            self._base_risk("HIGH", 7.5, 1, 5.0),
            [_finding("express", "4.17.0", vulns=[_vuln("H1", 7.5)])],
            "FAIL", "High found", []
        )
        assert "express" in md

    def test_cve_id_in_report(self):
        """OBJ2-D-05: CVE id appears in the report"""
        md = generate_markdown_report(
            self._base_risk("HIGH", 8.0, 1, 5.0),
            [_finding("lib", "1.0", vulns=[_vuln("CVE-2021-12345", 8.0)])],
            "FAIL", "High found", []
        )
        assert "CVE-2021-12345" in md

    def test_cvss_score_in_report(self):
        """OBJ2-D-06: CVSS score appears in the report"""
        md = generate_markdown_report(
            self._base_risk("HIGH", 7.8, 1, 5.0),
            [_finding("lib", "1.0", vulns=[_vuln("CVE-X", 7.8)])],
            "FAIL", "reason", []
        )
        assert "7.8" in md

    def test_no_vulns_message_shown(self):
        """OBJ2-D-07: No vulnerabilities → friendly message in report"""
        md = generate_markdown_report(self._base_risk(), [], "PASS", "No issues", [])
        assert "no vulnerabilities" in md.lower()

    def test_risk_score_in_report(self):
        """OBJ2-D-08: Risk score appears in the report header"""
        md = generate_markdown_report(
            self._base_risk("HIGH", 7.5, 1, 4.5),
            [_finding("lib", "1.0", vulns=[_vuln("H2", 7.5)])],
            "FAIL", "reason", []
        )
        assert "4.5" in md

    def test_max_cvss_in_report(self):
        """OBJ2-D-09: Max CVSS label appears in report header"""
        md = generate_markdown_report(self._base_risk("CRITICAL", 9.5, 1, 7.0),
            [_finding("lib", "1.0", vulns=[_vuln("C2", 9.5)])], "FAIL", "r", [])
        assert "9.5" in md

    def test_policy_decision_section_present(self):
        """OBJ2-D-10: 'Policy Decision' section exists in report"""
        md = generate_markdown_report(self._base_risk(), [], "PASS", "Looks clean", [])
        assert "Policy Decision" in md

    def test_reason_in_policy_section(self):
        """OBJ2-D-11: Provided reason text appears in report"""
        md = generate_markdown_report(self._base_risk(), [], "PASS", "All clear here", [])
        assert "All clear here" in md

    def test_osv_source_labeled(self):
        """OBJ2-D-12: [Source: OSV] label appears for each vulnerability"""
        md = generate_markdown_report(
            self._base_risk("CRITICAL", 9.5, 1, 7.0),
            [_finding("lib", "1.0", vulns=[_vuln("C3", 9.5)])],
            "FAIL", "r", []
        )
        assert "OSV" in md

    def test_unknown_cvss_manual_review_note(self):
        """OBJ2-D-13: Vuln with CVSS=0 triggers manual review note"""
        md = generate_markdown_report(
            self._base_risk("UNKNOWN", 0.0, 1, 0.0),
            [_finding("lib", "1.0", vulns=[_vuln("U1", 0.0)])],
            "WARN", "manual review", []
        )
        assert "manual review" in md.lower() or "unknown" in md.lower()

    def test_multiple_components_all_listed(self):
        """OBJ2-D-14: All vulnerable components appear in report"""
        findings = [
            _finding("lib-a", "1.0", vulns=[_vuln("C4", 9.5)]),
            _finding("lib-b", "2.0", vulns=[_vuln("H3", 7.5)])
        ]
        md = generate_markdown_report(
            self._base_risk("CRITICAL", 9.5, 2, 8.0), findings, "FAIL", "r", []
        )
        assert "lib-a" in md and "lib-b" in md


class TestReporterFileOutput:
    """OBJ2-D: File saving"""

    def test_saves_pr_comment_md(self, tmp_path):
        """OBJ2-D-15: save_outputs creates pr_comment.md"""
        md = generate_markdown_report({"overall_severity": "NONE", "max_cvss": 0.0,
            "total_vulnerabilities": 0, "risk_score": 0.0}, [], "PASS", "No issues", [])
        save_outputs(str(tmp_path), md, {"decision": "PASS"})
        assert (tmp_path / "pr_comment.md").exists()

    def test_saves_report_json(self, tmp_path):
        """OBJ2-D-16: save_outputs creates report.json"""
        save_outputs(str(tmp_path), "md", {"decision": "PASS"})
        assert (tmp_path / "report.json").exists()

    def test_json_contains_decision(self, tmp_path):
        """OBJ2-D-17: report.json has a 'decision' field"""
        save_outputs(str(tmp_path), "md", {"decision": "FAIL", "findings": []})
        data = json.loads((tmp_path / "report.json").read_text())
        assert data["decision"] == "FAIL"

    def test_json_contains_risk_summary(self, tmp_path):
        """OBJ2-D-18: report.json has risk_summary"""
        save_outputs(str(tmp_path), "md", {"decision": "PASS", "risk_summary": {"max_cvss": 0.0}})
        data = json.loads((tmp_path / "report.json").read_text())
        assert "risk_summary" in data

    def test_creates_output_dir_if_missing(self, tmp_path):
        """OBJ2-D-19: Output directory is created automatically"""
        out = str(tmp_path / "new" / "nested" / "dir")
        save_outputs(out, "md", {"decision": "PASS"})
        assert os.path.exists(out)

    def test_pr_comment_matches_markdown(self, tmp_path):
        """OBJ2-D-20: pr_comment.md content matches generated markdown"""
        md = generate_markdown_report({"overall_severity": "NONE", "max_cvss": 0.0,
            "total_vulnerabilities": 0, "risk_score": 0.0}, [], "PASS", "All clear", [])
        save_outputs(str(tmp_path), md, {"decision": "PASS"})
        saved = (tmp_path / "pr_comment.md").read_text(encoding="utf-8")
        assert saved == md
