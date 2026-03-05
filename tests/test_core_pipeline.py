"""
PRISM Core Pipeline - Comprehensive Test Suite
===============================================

Tests the full basic pipeline end-to-end:
  SBOM → Parse → OSV Scan → Risk Score → Policy Gate → Remediation → Report

Test Classes:
  1. TestSBOMParser          - CycloneDX JSON parsing, purl extraction
  2. TestOSVClient           - OSV API querying, error handling
  3. TestRiskEngine          - Risk score computation, CVSS mapping
  4. TestPolicyEngine        - PASS/WARN/FAIL decisions, custom rules
  5. TestRemediationAdvisor  - Fix suggestion generation
  6. TestReporter            - Markdown report and file output
  7. TestEndToEndPipeline    - Full pipeline scenarios
"""

import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.sbom_parser import load_sbom, extract_components, parse_purl
from agent.osv_client import query_osv
from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy
from agent.remediation_advisor import generate_remediation_summary
from agent.reporter import generate_markdown_report, save_outputs


# ==============================================================================
# 1. SBOM PARSER TESTS
# ==============================================================================

class TestSBOMParser:
    """Tests for SBOM parsing: loading, component extraction, purl decoding"""

    def test_parse_valid_cyclonedx_sbom(self, tmp_path):
        """PARSER-1: Load a well-formed CycloneDX SBOM and extract components"""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}
            ]
        }
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))

        loaded = load_sbom(str(f))
        components = extract_components(loaded)

        assert len(components) == 1
        assert components[0]["name"] == "lodash"
        assert components[0]["version"] == "4.17.15"

    def test_parse_empty_sbom(self, tmp_path):
        """PARSER-2: SBOM with no components → empty list"""
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))

        components = extract_components(load_sbom(str(f)))
        assert components == []

    def test_parse_multiple_components(self, tmp_path):
        """PARSER-3: SBOM with 5 components → all 5 extracted"""
        packages = [
            {"name": f"pkg-{i}", "version": f"1.{i}.0", "purl": f"pkg:npm/pkg-{i}@1.{i}.0"}
            for i in range(5)
        ]
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": packages}
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))

        components = extract_components(load_sbom(str(f)))
        assert len(components) == 5

    def test_parse_purl_npm(self):
        """PARSER-4: npm purl → ecosystem=npm"""
        ecosystem, name = parse_purl("pkg:npm/lodash@4.17.15")
        assert ecosystem == "npm"
        assert name == "lodash"

    def test_parse_purl_pypi(self):
        """PARSER-5: PyPI purl → ecosystem=PyPI"""
        ecosystem, name = parse_purl("pkg:pypi/requests@2.25.0")
        assert ecosystem == "PyPI"
        assert name == "requests"

    def test_parse_purl_maven(self):
        """PARSER-6: Maven purl → namespace:name format"""
        ecosystem, name = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        assert ecosystem == "Maven"
        assert "log4j-core" in name

    def test_parse_component_without_purl(self, tmp_path):
        """PARSER-7: Component with no purl → uses plain name"""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "my-lib", "version": "2.0.0"}  # No purl
            ]
        }
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))

        components = extract_components(load_sbom(str(f)))
        assert len(components) == 1
        assert components[0]["name"] == "my-lib"

    def test_parse_component_missing_version_excluded(self, tmp_path):
        """PARSER-8: Component without version → excluded from results"""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "has-version", "version": "1.0.0"},
                {"name": "no-version"}  # No version key
            ]
        }
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))

        components = extract_components(load_sbom(str(f)))
        names = [c["name"] for c in components]
        assert "has-version" in names
        assert "no-version" not in names

    def test_parse_mixed_ecosystems(self, tmp_path):
        """PARSER-9: SBOM with npm + PyPI + Maven → all ecosystems extracted"""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
                {"name": "requests", "version": "2.25.0", "purl": "pkg:pypi/requests@2.25.0"},
                {"name": "log4j-core", "version": "2.14.1",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
            ]
        }
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))

        components = extract_components(load_sbom(str(f)))
        ecosystems = {c.get("ecosystem") for c in components}
        assert "npm" in ecosystems
        assert "PyPI" in ecosystems
        assert "Maven" in ecosystems


# ==============================================================================
# 2. OSV CLIENT TESTS
# ==============================================================================

class TestOSVClient:
    """Tests for the OSV vulnerability querying client"""

    def test_osv_timeout_returns_empty(self):
        """OSV-1: On timeout, returns empty list (no crash)"""
        import requests
        with patch("requests.post", side_effect=requests.exceptions.Timeout()):
            result = query_osv("lodash", "4.17.15", "npm")
        assert result == []

    def test_osv_connection_error_returns_empty(self):
        """OSV-2: On connection error, returns empty list gracefully"""
        import requests
        with patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
            result = query_osv("lodash", "4.17.15", "npm")
        assert result == []

    def test_osv_500_error_returns_empty(self):
        """OSV-3: On HTTP 500 response, returns empty list gracefully"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("500 Server Error")
        with patch("requests.post", return_value=mock_resp):
            result = query_osv("some-package", "1.0.0")
        assert result == []

    def test_osv_no_vulns_returns_empty(self):
        """OSV-4: Safe package with no known CVEs → empty list"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"vulns": []}  # No vulns
        with patch("requests.post", return_value=mock_resp):
            result = query_osv("lodash", "4.17.21", "npm")
        assert result == []

    def test_osv_vuln_with_cvss_parsed(self):
        """OSV-5: Vulnerability with CVSS score → score extracted correctly"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "vulns": [{
                "id": "CVE-2021-23337",
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                "database_specific": {}
            }]
        }
        with patch("requests.post", return_value=mock_resp):
            result = query_osv("lodash", "4.17.15", "npm")
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2021-23337"
        assert result[0]["cvss"] == 9.8

    def test_osv_vuln_without_cvss_gets_zero(self):
        """OSV-6: Vulnerability with no CVSS data → cvss=0.0 (manual review flag)"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "vulns": [{
                "id": "GHSA-xxxx-yyyy-zzzz",
                "database_specific": {}  # No severity field
            }]
        }
        with patch("requests.post", return_value=mock_resp):
            result = query_osv("some-pkg", "1.0.0")
        assert len(result) == 1
        assert result[0]["cvss"] == 0.0
        assert result[0]["has_cvss"] is False

    def test_osv_multiple_vulns_same_package(self):
        """OSV-7: Package with 3 CVEs → all 3 returned"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "vulns": [
                {"id": "CVE-2021-23337", "severity": [{"type": "CVSS_V3", "score": "9.8"}], "database_specific": {}},
                {"id": "CVE-2020-28500", "severity": [{"type": "CVSS_V3", "score": "5.3"}], "database_specific": {}},
                {"id": "CVE-2019-10744", "severity": [{"type": "CVSS_V3", "score": "9.8"}], "database_specific": {}},
            ]
        }
        with patch("requests.post", return_value=mock_resp):
            result = query_osv("lodash", "4.17.15", "npm")
        assert len(result) == 3
        ids = [v["id"] for v in result]
        assert "CVE-2021-23337" in ids
        assert "CVE-2020-28500" in ids

    def test_osv_severity_from_database_specific(self):
        """OSV-8: CVSS from database_specific.severity text → mapped to numeric"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "vulns": [{
                "id": "CVE-2020-1234",
                "database_specific": {"severity": "CRITICAL"}
            }]
        }
        with patch("requests.post", return_value=mock_resp):
            result = query_osv("some-pkg", "1.0.0")
        assert len(result) == 1
        # CRITICAL should map to a numeric value > 0
        assert result[0]["cvss"] > 0.0


# ==============================================================================
# 3. RISK ENGINE TESTS
# ==============================================================================

class TestRiskEngine:
    """Tests for the risk score computation module"""

    def _make_findings(self, vulns_list):
        """Helper: build findings list from simplified vuln dicts"""
        return [{
            "component": {"name": "test-pkg", "version": "1.0.0"},
            "vulnerabilities": vulns_list
        }]

    def test_risk_zero_vulnerabilities(self):
        """RISK-1: No vulnerabilities → risk_score=0, total=0, severity=UNKNOWN"""
        findings = [{"component": {"name": "safe-pkg", "version": "1.0.0"}, "vulnerabilities": []}]
        result = compute_risk(findings)
        assert result["total_vulnerabilities"] == 0
        assert result["risk_score"] == 0.0

    def test_risk_single_critical_cvss(self):
        """RISK-2: Single CRITICAL (CVSS 9.8) → overall_severity=CRITICAL"""
        findings = self._make_findings([{"id": "CVE-001", "cvss": 9.8}])
        result = compute_risk(findings)
        assert result["max_cvss"] == 9.8
        assert result["overall_severity"] == "CRITICAL"
        assert result["total_vulnerabilities"] == 1

    def test_risk_single_high_cvss(self):
        """RISK-3: Single HIGH (CVSS 7.5) → overall_severity=HIGH"""
        findings = self._make_findings([{"id": "CVE-002", "cvss": 7.5}])
        result = compute_risk(findings)
        assert result["overall_severity"] == "HIGH"

    def test_risk_single_medium_cvss(self):
        """RISK-4: Single MEDIUM (CVSS 5.0) → overall_severity=MEDIUM"""
        findings = self._make_findings([{"id": "CVE-003", "cvss": 5.0}])
        result = compute_risk(findings)
        assert result["overall_severity"] == "MEDIUM"

    def test_risk_single_low_cvss(self):
        """RISK-5: Single LOW (CVSS 2.0) → overall_severity=LOW"""
        findings = self._make_findings([{"id": "CVE-004", "cvss": 2.0}])
        result = compute_risk(findings)
        assert result["overall_severity"] == "LOW"

    def test_risk_max_cvss_drives_severity(self):
        """RISK-6: Mix of MEDIUM + CRITICAL → max_cvss=CRITICAL drives severity"""
        findings = self._make_findings([
            {"id": "CVE-005", "cvss": 5.0},  # MEDIUM
            {"id": "CVE-006", "cvss": 9.8},  # CRITICAL
        ])
        result = compute_risk(findings)
        assert result["max_cvss"] == 9.8
        assert result["overall_severity"] == "CRITICAL"

    def test_risk_multiple_vulns_higher_score(self):
        """RISK-7: Multiple vulns → risk_score higher than a single-vuln scan"""
        single = compute_risk(self._make_findings([{"id": "CVE-007", "cvss": 7.5}]))
        multi = compute_risk(self._make_findings([
            {"id": "CVE-007", "cvss": 7.5},
            {"id": "CVE-008", "cvss": 7.5},
            {"id": "CVE-009", "cvss": 7.5},
        ]))
        assert multi["risk_score"] > single["risk_score"]

    def test_risk_score_capped_at_10(self):
        """RISK-8: 20 critical vulns → risk_score is ≤ 10"""
        vulns = [{"id": f"CVE-{i:03d}", "cvss": 9.8} for i in range(20)]
        findings = self._make_findings(vulns)
        result = compute_risk(findings)
        assert result["risk_score"] <= 10.0

    def test_risk_unknown_cvss_zero_score(self):
        """RISK-9: Vuln with cvss=0.0 (no CVSS) → counts in total but doesn't inflate risk"""
        findings = self._make_findings([{"id": "CVE-UNKNOWN", "cvss": 0.0}])
        result = compute_risk(findings)
        assert result["total_vulnerabilities"] == 1
        assert result["max_cvss"] == 0.0

    def test_risk_multiple_components_aggregated(self):
        """RISK-10: 3 components each with a vuln → total=3, max taken across all"""
        findings = [
            {"component": {"name": "pkg-a", "version": "1.0"}, "vulnerabilities": [{"id": "A", "cvss": 9.8}]},
            {"component": {"name": "pkg-b", "version": "1.0"}, "vulnerabilities": [{"id": "B", "cvss": 5.0}]},
            {"component": {"name": "pkg-c", "version": "1.0"}, "vulnerabilities": [{"id": "C", "cvss": 7.5}]},
        ]
        result = compute_risk(findings)
        assert result["total_vulnerabilities"] == 3
        assert result["max_cvss"] == 9.8
        assert result["overall_severity"] == "CRITICAL"


# ==============================================================================
# 4. POLICY ENGINE TESTS
# ==============================================================================

class TestPolicyEngine:
    """Tests for the policy evaluation: PASS / WARN / FAIL decisions"""

    def _risk(self, severity="UNKNOWN", total=0, max_cvss=0.0):
        return {
            "overall_severity": severity,
            "total_vulnerabilities": total,
            "max_cvss": max_cvss,
            "risk_score": max_cvss * 0.6
        }

    def _findings(self, vulns=None, pkg_name="test-pkg"):
        return [{
            "component": {"name": pkg_name, "version": "1.0.0"},
            "vulnerabilities": vulns or []
        }]

    def test_policy_no_vulnerabilities_pass(self):
        """POLICY-1: No vulnerabilities → PASS"""
        decision, reason = evaluate_policy(self._risk(), self._findings())
        assert decision == "PASS"

    def test_policy_critical_vulnerability_fail(self):
        """POLICY-2: CRITICAL severity → FAIL"""
        vulns = [{"id": "CVE-001", "cvss": 9.8}]
        risk = self._risk("CRITICAL", 1, 9.8)
        decision, reason = evaluate_policy(risk, self._findings(vulns))
        assert decision == "FAIL"

    def test_policy_high_vulnerability_fail(self):
        """POLICY-3: HIGH severity → FAIL"""
        vulns = [{"id": "CVE-002", "cvss": 7.5}]
        risk = self._risk("HIGH", 1, 7.5)
        decision, reason = evaluate_policy(risk, self._findings(vulns))
        assert decision == "FAIL"

    def test_policy_medium_vulnerability_warn(self):
        """POLICY-4: MEDIUM severity → WARN"""
        vulns = [{"id": "CVE-003", "cvss": 5.0}]
        risk = self._risk("MEDIUM", 1, 5.0)
        decision, reason = evaluate_policy(risk, self._findings(vulns))
        assert decision == "WARN"

    def test_policy_low_vulnerability_pass(self):
        """POLICY-5: LOW severity only → PASS"""
        vulns = [{"id": "CVE-004", "cvss": 2.0}]
        risk = self._risk("LOW", 1, 2.0)
        decision, reason = evaluate_policy(risk, self._findings(vulns))
        assert decision == "PASS"

    def test_policy_unknown_cvss_warn(self):
        """POLICY-6: Vulnerability with CVSS=0.0 (UNKNOWN) → WARN (manual review)"""
        vulns = [{"id": "CVE-005", "cvss": 0.0}]
        risk = self._risk("UNKNOWN", 1, 0.0)
        decision, reason = evaluate_policy(risk, self._findings(vulns))
        assert decision == "WARN"

    def test_policy_blocked_package_fail(self):
        """POLICY-7: Blocked package in SBOM → FAIL regardless of CVSS"""
        rules = {"blocked_packages": ["openssl"]}
        vulns = [{"id": "CVE-006", "cvss": 2.0}]  # Low severity
        risk = self._risk("LOW", 1, 2.0)
        findings = self._findings(vulns, pkg_name="openssl")
        decision, reason = evaluate_policy(risk, findings, rules)
        assert decision == "FAIL"
        assert "openssl" in reason

    def test_policy_custom_fail_on_critical(self):
        """POLICY-8: Custom rules with fail_on=[CRITICAL] → FAIL on critical"""
        rules = {"policy_gates": {"fail_on": ["CRITICAL"], "warn_on": ["HIGH", "MEDIUM"]}}
        vulns = [{"id": "CVE-007", "cvss": 9.8}]
        risk = self._risk("CRITICAL", 1, 9.8)
        decision, reason = evaluate_policy(risk, self._findings(vulns), rules)
        assert decision == "FAIL"

    def test_policy_custom_warn_on_high(self):
        """POLICY-9: Custom rules with warn_on=[HIGH] (not fail) → WARN on HIGH"""
        rules = {"policy_gates": {"fail_on": ["CRITICAL"], "warn_on": ["HIGH", "MEDIUM"]}}
        vulns = [{"id": "CVE-008", "cvss": 7.5}]
        risk = self._risk("HIGH", 1, 7.5)
        decision, reason = evaluate_policy(risk, self._findings(vulns), rules)
        assert decision == "WARN"

    def test_policy_no_rules_uses_defaults(self):
        """POLICY-10: No rules file → default FAIL on CRITICAL/HIGH"""
        vulns = [{"id": "CVE-009", "cvss": 8.0}]
        risk = self._risk("HIGH", 1, 8.0)
        decision, reason = evaluate_policy(risk, self._findings(vulns), rules=None)
        assert decision == "FAIL"

    def test_policy_reason_string_populated(self):
        """POLICY-11: Decision reason message is always non-empty"""
        risk = self._risk("CRITICAL", 1, 9.8)
        vulns = [{"id": "CVE-010", "cvss": 9.8}]
        decision, reason = evaluate_policy(risk, self._findings(vulns))
        assert isinstance(reason, str) and len(reason) > 0

    def test_policy_multiple_components_worst_wins(self):
        """POLICY-12: 3 components (LOW, MEDIUM, CRITICAL) → FAIL due to CRITICAL"""
        findings = [
            {"component": {"name": "a", "version": "1.0"}, "vulnerabilities": [{"id": "A", "cvss": 2.0}]},
            {"component": {"name": "b", "version": "1.0"}, "vulnerabilities": [{"id": "B", "cvss": 5.0}]},
            {"component": {"name": "c", "version": "1.0"}, "vulnerabilities": [{"id": "C", "cvss": 9.8}]},
        ]
        risk = self._risk("CRITICAL", 3, 9.8)
        decision, reason = evaluate_policy(risk, findings)
        assert decision == "FAIL"


# ==============================================================================
# 5. REMEDIATION ADVISOR TESTS
# ==============================================================================

class TestRemediationAdvisor:
    """Tests for the basic remediation suggestion generator"""

    def test_remediation_generated_for_vulnerable_package(self):
        """REMED-1: Vulnerable component → generates at least one recommendation"""
        findings = [{
            "component": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": "CVE-2021-23337",
                "cvss": 9.8,
                "raw_data": {
                    "affected": [{
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
                    }]
                }
            }]
        }]
        remediations = generate_remediation_summary(findings)
        assert remediations is not None
        assert len(remediations) > 0

    def test_remediation_empty_for_clean_sbom(self):
        """REMED-2: Clean SBOM (no vulnerabilities) → no recommendations"""
        findings = [{"component": {"name": "lodash", "version": "4.17.21"}, "vulnerabilities": []}]
        remediations = generate_remediation_summary(findings)
        # Either empty list or None is acceptable
        assert not remediations or all(r.get("action") in [None, "No action needed", ""] for r in remediations)

    def test_remediation_includes_upgrade_suggestion(self):
        """REMED-3: Fixed version in OSV data → upgrade command present in advice"""
        findings = [{
            "component": {"name": "axios", "version": "0.21.0", "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": "CVE-2021-3749",
                "cvss": 7.5,
                "raw_data": {
                    "affected": [{
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.21.2"}]}]
                    }]
                }
            }]
        }]
        remediations = generate_remediation_summary(findings)
        # Check that the advisory mentions the fixed version or upgrade
        remediation_text = str(remediations)
        assert "0.21.2" in remediation_text or "upgrade" in remediation_text.lower() or "update" in remediation_text.lower()

    def test_ai_remediation_fallback_no_key(self):
        """REMED-4: No OpenAI API key → falls back to basic remediation without crashing"""
        from agent.ai_remediation_advisor import generate_ai_remediation_summary
        findings = [{
            "component": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "CVE-2021-23337", "cvss": 9.8}]
        }]
        with patch.dict(os.environ, {}, clear=False):
            # Ensure no API key is set
            os.environ.pop("OPENAI_API_KEY", None)
            result = generate_ai_remediation_summary(findings)
        # Should not crash and should return something
        assert result is not None

    def test_remediation_multiple_components(self):
        """REMED-5: Two vulnerable components → one remediation entry per component"""
        findings = [
            {
                "component": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                "vulnerabilities": [{"id": "CVE-001", "cvss": 9.8, "raw_data": {}}]
            },
            {
                "component": {"name": "axios", "version": "0.21.0", "ecosystem": "npm"},
                "vulnerabilities": [{"id": "CVE-002", "cvss": 7.5, "raw_data": {}}]
            }
        ]
        remediations = generate_remediation_summary(findings)
        assert remediations is not None
        assert len(remediations) >= 2


# ==============================================================================
# 6. REPORTER TESTS
# ==============================================================================

class TestReporter:
    """Tests for markdown report generation and file output"""

    def _base_risk(self, severity="CRITICAL", total=1, max_cvss=9.8):
        return {
            "overall_severity": severity,
            "total_vulnerabilities": total,
            "max_cvss": max_cvss,
            "risk_score": 8.0
        }

    def _findings(self, severity="CRITICAL", cvss=9.8):
        return [{
            "component": {"name": "lodash", "version": "4.17.15"},
            "vulnerabilities": [{"id": "CVE-2021-23337", "cvss": cvss, "source": "OSV"}]
        }]

    def test_report_fail_decision_symbol(self):
        """REPORT-1: FAIL decision → report contains ✗ symbol"""
        md = generate_markdown_report(self._base_risk(), self._findings(), "FAIL", "Critical found", [])
        assert "✗" in md or "FAIL" in md

    def test_report_pass_decision_symbol(self):
        """REPORT-2: PASS decision → report contains ✓ symbol"""
        risk = self._base_risk("LOW", 0, 0.0)
        md = generate_markdown_report(risk, [], "PASS", "No issues", [])
        assert "✓" in md or "PASS" in md

    def test_report_warn_decision_symbol(self):
        """REPORT-3: WARN decision → report contains ! symbol"""
        risk = self._base_risk("MEDIUM", 1, 5.0)
        findings = [{"component": {"name": "minimist", "version": "1.2.0"},
                     "vulnerabilities": [{"id": "CVE-003", "cvss": 5.0, "source": "OSV"}]}]
        md = generate_markdown_report(risk, findings, "WARN", "Medium severity", [])
        assert "!" in md or "WARN" in md

    def test_report_includes_component_name(self):
        """REPORT-4: Report lists the vulnerable component name"""
        md = generate_markdown_report(self._base_risk(), self._findings(), "FAIL", "Critical", [])
        assert "lodash" in md

    def test_report_includes_cve_id(self):
        """REPORT-5: Report includes the CVE identifier"""
        md = generate_markdown_report(self._base_risk(), self._findings(), "FAIL", "Critical", [])
        assert "CVE-2021-23337" in md

    def test_report_no_vulnerabilities_message(self):
        """REPORT-6: Clean SBOM → report says no vulnerabilities"""
        risk = self._base_risk("UNKNOWN", 0, 0.0)
        md = generate_markdown_report(risk, [{"component": {"name": "a", "version": "1.0"}, "vulnerabilities": []}],
                                      "PASS", "No issues", [])
        assert "No vulnerabilities" in md or "no vulnerabilities" in md.lower()

    def test_report_saves_pr_comment_md(self, tmp_path):
        """REPORT-7: save_outputs creates pr_comment.md"""
        md = "# Test Report\nPASS"
        save_outputs(str(tmp_path), md, {"decision": "PASS"})
        assert (tmp_path / "pr_comment.md").exists()

    def test_report_saves_report_json(self, tmp_path):
        """REPORT-8: save_outputs creates report.json"""
        md = "# Test Report\nPASS"
        save_outputs(str(tmp_path), md, {"decision": "PASS", "risk_score": 0.0})
        assert (tmp_path / "report.json").exists()

    def test_report_json_contains_decision(self, tmp_path):
        """REPORT-9: report.json contains the decision field"""
        save_outputs(str(tmp_path), "# Report", {"decision": "FAIL", "total_vulns": 3})
        with open(tmp_path / "report.json") as f:
            data = json.load(f)
        assert data.get("decision") == "FAIL"

    def test_report_creates_output_dir_if_missing(self, tmp_path):
        """REPORT-10: save_outputs creates output directory if it doesn't exist"""
        output_dir = str(tmp_path / "new-output-dir")
        save_outputs(output_dir, "# Report", {"decision": "PASS"})
        assert Path(output_dir).exists()


# ==============================================================================
# 7. END-TO-END PIPELINE TESTS
# ==============================================================================

class TestEndToEndPipeline:
    """Full pipeline: SBOM → parse → OSV scan (mocked) → risk → policy → report"""

    def _run_pipeline(self, sbom_components, mock_osv_vulns_map, rules=None, tmp_path=None):
        """
        Helper: run the full pipeline with mocked OSV responses.

        mock_osv_vulns_map: dict of {(name, version): [vuln_list]}
        Returns: (decision, reason, markdown, risk_summary)
        """
        from agent.sbom_parser import extract_components

        sbom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": sbom_components
        }
        components = extract_components(sbom_json)

        findings = []
        for comp in components:
            key = (comp["name"], comp["version"])
            vulns = mock_osv_vulns_map.get(key, [])
            findings.append({"component": comp, "vulnerabilities": vulns})

        risk = compute_risk(findings)
        decision, reason = evaluate_policy(risk, findings, rules)
        remediations = generate_remediation_summary(findings)
        md = generate_markdown_report(risk, findings, decision, reason, remediations)

        if tmp_path:
            save_outputs(str(tmp_path), md, {"decision": decision, "risk_summary": risk})

        return decision, reason, md, risk

    def test_e2e_clean_sbom_passes(self, tmp_path):
        """E2E-1: All safe packages → pipeline ends with PASS"""
        components = [{"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}]
        osv_map = {("lodash", "4.17.21"): []}  # No vulns

        decision, reason, md, risk = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert decision == "PASS"
        assert (tmp_path / "pr_comment.md").exists()

    def test_e2e_critical_vuln_fails(self, tmp_path):
        """E2E-2: Critical vulnerability found → FAIL"""
        components = [{"name": "lodash", "version": "4.17.15"}]
        osv_map = {("lodash", "4.17.15"): [{"id": "CVE-2021-23337", "cvss": 9.8}]}

        decision, reason, md, risk = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert decision == "FAIL"
        assert risk["overall_severity"] == "CRITICAL"

    def test_e2e_medium_vuln_warns(self, tmp_path):
        """E2E-3: Medium severity only → WARN"""
        components = [{"name": "some-pkg", "version": "1.0.0"}]
        osv_map = {("some-pkg", "1.0.0"): [{"id": "CVE-MEDIUM", "cvss": 5.0}]}

        decision, reason, md, risk = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert decision == "WARN"

    def test_e2e_multiple_components_one_vulnerable(self, tmp_path):
        """E2E-4: 3 components, only 1 vulnerable (critical) → FAIL"""
        components = [
            {"name": "lodash",   "version": "4.17.15"},
            {"name": "express",  "version": "4.18.2"},  # safe
            {"name": "minimist", "version": "1.2.6"},   # safe
        ]
        osv_map = {
            ("lodash",   "4.17.15"): [{"id": "CVE-2021-23337", "cvss": 9.8}],
            ("express",  "4.18.2"):  [],
            ("minimist", "1.2.6"):   [],
        }

        decision, reason, md, risk = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert decision == "FAIL"
        assert risk["total_vulnerabilities"] == 1

    def test_e2e_all_safe_multiple_components(self, tmp_path):
        """E2E-5: Multiple components, all clean → PASS"""
        components = [
            {"name": "express",  "version": "4.18.2"},
            {"name": "chalk",    "version": "5.3.0"},
            {"name": "dayjs",    "version": "1.11.10"},
        ]
        osv_map = {k: [] for k in [("express", "4.18.2"), ("chalk", "5.3.0"), ("dayjs", "1.11.10")]}

        decision, _, md, _ = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert decision == "PASS"

    def test_e2e_blocked_package_fails_even_no_cvss(self, tmp_path):
        """E2E-6: Blocked package with no CVSS → FAIL due to policy rule"""
        rules = {"blocked_packages": ["openssl"]}
        components = [{"name": "openssl", "version": "1.0.0"}]
        osv_map = {("openssl", "1.0.0"): []}  # No CVEs but blocked

        decision, reason, md, _ = self._run_pipeline(components, osv_map, rules=rules, tmp_path=tmp_path)
        assert decision == "FAIL"
        assert "openssl" in reason

    def test_e2e_output_files_created(self, tmp_path):
        """E2E-7: Pipeline always creates both pr_comment.md and report.json"""
        components = [{"name": "lodash", "version": "4.17.15"}]
        osv_map = {("lodash", "4.17.15"): [{"id": "CVE-001", "cvss": 9.8}]}

        self._run_pipeline(components, osv_map, tmp_path=tmp_path)

        assert (tmp_path / "pr_comment.md").exists()
        assert (tmp_path / "report.json").exists()

    def test_e2e_report_matches_decision(self, tmp_path):
        """E2E-8: The text in pr_comment.md reflects the actual decision"""
        components = [{"name": "lodash", "version": "4.17.15"}]
        osv_map = {("lodash", "4.17.15"): [{"id": "CVE-001", "cvss": 9.8}]}

        decision, _, md, _ = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert "FAIL" in md

    def test_e2e_empty_sbom_passes(self, tmp_path):
        """E2E-9: Empty SBOM (no components) → PASS"""
        decision, _, _, risk = self._run_pipeline([], {}, tmp_path=tmp_path)
        assert decision == "PASS"
        assert risk["total_vulnerabilities"] == 0

    def test_e2e_risk_score_in_report(self, tmp_path):
        """E2E-10: Risk score is present in the generated markdown report"""
        components = [{"name": "lodash", "version": "4.17.15"}]
        osv_map = {("lodash", "4.17.15"): [{"id": "CVE-001", "cvss": 9.8}]}

        _, _, md, _ = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert "Risk Score" in md

    def test_e2e_high_vuln_fails_by_default(self, tmp_path):
        """E2E-11: HIGH severity (CVSS 8.0) → FAIL under default policy"""
        components = [{"name": "axios", "version": "0.21.0"}]
        osv_map = {("axios", "0.21.0"): [{"id": "CVE-HIGH", "cvss": 8.0}]}

        decision, _, _, _ = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert decision == "FAIL"

    def test_e2e_low_vuln_passes_default_policy(self, tmp_path):
        """E2E-12: LOW severity only (CVSS 2.0) → PASS under default policy"""
        components = [{"name": "minor-pkg", "version": "1.0.0"}]
        osv_map = {("minor-pkg", "1.0.0"): [{"id": "CVE-LOW", "cvss": 2.0}]}

        decision, _, _, _ = self._run_pipeline(components, osv_map, tmp_path=tmp_path)
        assert decision == "PASS"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
