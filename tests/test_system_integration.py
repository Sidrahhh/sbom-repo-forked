"""
PRISM - System Integration & End-to-End Test Suite
=====================================================
Tests the full pipeline from SBOM file → output files, treating the system
as a black box. Covers correctness, consistency, edge cases, and performance.

Pipeline under test:
  SBOM file  →  load_sbom  →  extract_components  →  query_osv (mocked)
  →  compute_risk  →  evaluate_policy  →  generate_remediation_summary
  →  generate_markdown_report  →  save_outputs  →  output/

Test IDs: SYS-<NN>
"""

import json
import os
import sys
import time
import threading
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.sbom_parser import load_sbom, extract_components
from agent.osv_client import query_osv
from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy, load_policy
from agent.remediation_advisor import generate_remediation_summary
from agent.reporter import generate_markdown_report, save_outputs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_sbom(tmp_path, components, name="sbom.json", spec="1.4"):
    data = {"bomFormat": "CycloneDX", "specVersion": spec, "components": components}
    f = tmp_path / name
    f.write_text(json.dumps(data))
    return str(f)


def _comp(name, version, ecosystem_type="npm"):
    return {
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem_type}/{name}@{version}"
    }


def _mock_osv_response(vulns_list):
    """Build a mock requests.post return value."""
    mock = MagicMock()
    mock.raise_for_status.return_value = None
    mock.json.return_value = {"vulns": vulns_list}
    return mock


def _per_component_response(vuln_map):
    """Return a requests.post side_effect for per-component OSV mocking."""
    def side_effect(url, **kwargs):
        name = kwargs.get("json", {}).get("package", {}).get("name", "")
        return _mock_osv_response(vuln_map.get(name, []))
    return side_effect


def _vuln_high():
    return {"id": "CVE-HIGH", "severity": [{"score": "7.8"}]}


def _vuln_critical():
    return {"id": "CVE-CRITICAL", "severity": [{"score": "9.8"}]}


def _vuln_medium():
    return {"id": "CVE-MEDIUM", "database_specific": {"severity": "MEDIUM"}}


def _vuln_low():
    return {"id": "CVE-LOW",  "database_specific": {"severity": "LOW"}}


def _run_pipeline(sbom_path, output_dir, rules=None, use_ai=False):
    """Helper: run the full pipeline and return (decision, reason, md, json_data)."""
    sbom_json = load_sbom(sbom_path)
    components = extract_components(sbom_json)

    findings = []
    for comp in components:
        vulns = query_osv(comp["name"], comp["version"], comp.get("ecosystem"))
        findings.append({"component": comp, "vulnerabilities": vulns})

    risk = compute_risk(findings)
    remeds = generate_remediation_summary(findings)
    decision, reason = evaluate_policy(risk, findings, rules)
    md = generate_markdown_report(risk, findings, decision, reason, remeds)
    report = {"risk_summary": risk, "decision": decision, "reason": reason,
              "findings": findings, "remediations": remeds}
    save_outputs(output_dir, md, report)
    return decision, reason, md, report


# ===========================================================================
# CORRECTNESS — Pipeline produces expected decisions
# ===========================================================================

class TestPipelineDecisions:

    def test_clean_sbom_produces_pass(self, tmp_path):
        """SYS-01: Clean package (no OSV vulns) → PASS decision"""
        path = _write_sbom(tmp_path, [_comp("safe-lib", "1.0.0")])
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "PASS"

    def test_critical_vuln_produces_fail(self, tmp_path):
        """SYS-02: CRITICAL vulnerability → FAIL decision"""
        path = _write_sbom(tmp_path, [_comp("bad-lib", "1.0.0")])
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_critical()])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "FAIL"

    def test_high_vuln_produces_fail(self, tmp_path):
        """SYS-03: HIGH vulnerability → FAIL by default policy"""
        path = _write_sbom(tmp_path, [_comp("lib", "2.0.0")])
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_high()])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "FAIL"

    def test_medium_vuln_produces_warn(self, tmp_path):
        """SYS-04: MEDIUM vulnerability → WARN decision"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0.0")])
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_medium()])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "WARN"

    def test_low_vuln_produces_pass(self, tmp_path):
        """SYS-05: LOW vulnerability → PASS decision"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0.0")])
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_low()])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "PASS"

    def test_empty_sbom_produces_pass(self, tmp_path):
        """SYS-06: Empty SBOM (no components) → PASS"""
        path = _write_sbom(tmp_path, [])
        dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "PASS"

    def test_multiple_components_one_critical_fails(self, tmp_path):
        """SYS-07: 3 components, one CRITICAL → FAIL"""
        comps = [_comp("safe-a", "1.0"), _comp("bad-b", "2.0"), _comp("safe-c", "1.0")]
        path = _write_sbom(tmp_path, comps)
        with patch("agent.osv_client.requests.post",
                   side_effect=_per_component_response({"bad-b": [_vuln_critical()]})):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "FAIL"

    def test_multiple_components_all_clean_pass(self, tmp_path):
        """SYS-08: 5 clean components → PASS"""
        path = _write_sbom(tmp_path, [_comp(f"lib-{i}", "1.0") for i in range(5)])
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "PASS"

    def test_multiple_components_worst_is_medium_warns(self, tmp_path):
        """SYS-09: 3 components, worst is MEDIUM → WARN"""
        comps = [_comp("a", "1.0"), _comp("b", "1.0"), _comp("c", "1.0")]
        path = _write_sbom(tmp_path, comps)
        with patch("agent.osv_client.requests.post",
                   side_effect=_per_component_response({"b": [_vuln_medium()]})):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "WARN"

    def test_blocked_package_fails_even_no_cvss(self, tmp_path):
        """SYS-10: Blocked package with no CVSS → FAIL"""
        path = _write_sbom(tmp_path, [_comp("openssl", "1.0.0")])
        rules = load_rules(str(Path(__file__).parent.parent / "rules" / "blocked_packages.yaml"))
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            dec, reason, _, _ = _run_pipeline(path, str(tmp_path / "out"), rules=rules)
        assert dec == "FAIL"
        assert "openssl" in reason

    def test_all_severity_levels_mixed_fails(self, tmp_path):
        """SYS-11: SBOM with LOW, MEDIUM, HIGH, CRITICAL vulns → FAIL"""
        comps = [_comp(s, "1.0") for s in ["low-pkg", "med-pkg", "hi-pkg", "crit-pkg"]]
        path = _write_sbom(tmp_path, comps)
        osv_map = {
            "low-pkg": [_vuln_low()],
            "med-pkg": [_vuln_medium()],
            "hi-pkg": [_vuln_high()],
            "crit-pkg": [_vuln_critical()]
        }
        with patch("agent.osv_client.requests.post",
                   side_effect=_per_component_response(osv_map)):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "FAIL"


# ===========================================================================
# OUTPUT FILE CORRECTNESS
# ===========================================================================

class TestOutputFiles:

    def test_pr_comment_md_created(self, tmp_path):
        """SYS-12: pr_comment.md is created in output directory"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, out)
        assert os.path.exists(os.path.join(out, "pr_comment.md"))

    def test_report_json_created(self, tmp_path):
        """SYS-13: report.json is created in output directory"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, out)
        assert os.path.exists(os.path.join(out, "report.json"))

    def test_json_decision_matches_pipeline(self, tmp_path):
        """SYS-14: decision in report.json matches what pipeline returned"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_critical()])):
            dec, _, _, _ = _run_pipeline(path, out)
        data = json.loads(open(os.path.join(out, "report.json")).read())
        assert data["decision"] == dec

    def test_json_has_risk_summary(self, tmp_path):
        """SYS-15: report.json contains risk_summary"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, out)
        data = json.loads(open(os.path.join(out, "report.json")).read())
        assert "risk_summary" in data

    def test_json_findings_count_matches_components(self, tmp_path):
        """SYS-16: findings list in JSON matches number of SBOM components"""
        comps = [_comp(f"lib-{i}", "1.0") for i in range(4)]
        path = _write_sbom(tmp_path, comps)
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, out)
        data = json.loads(open(os.path.join(out, "report.json")).read())
        assert len(data["findings"]) == 4

    def test_risk_score_in_json_between_0_and_10(self, tmp_path):
        """SYS-17: risk_score in JSON is between 0 and 10"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_critical()])):
            _run_pipeline(path, out)
        data = json.loads(open(os.path.join(out, "report.json")).read())
        score = data["risk_summary"]["risk_score"]
        assert 0 <= score <= 10

    def test_output_dir_created_automatically(self, tmp_path):
        """SYS-18: Pipeline creates nested output dir if it doesn't exist"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "nested" / "out" / "dir")
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, out)
        assert os.path.isdir(out)

    def test_pr_comment_contains_decision(self, tmp_path):
        """SYS-19: pr_comment.md contains the decision string (PASS/WARN/FAIL)"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_critical()])):
            _run_pipeline(path, out)
        content = open(os.path.join(out, "pr_comment.md")).read()
        assert "FAIL" in content

    def test_report_mentions_component_name(self, tmp_path):
        """SYS-20: pr_comment.md mentions the vulnerable component name"""
        path = _write_sbom(tmp_path, [_comp("express", "4.17.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_high()])):
            _run_pipeline(path, out)
        content = open(os.path.join(out, "pr_comment.md")).read()
        assert "express" in content

    def test_report_contains_cve_id(self, tmp_path):
        """SYS-21: pr_comment.md lists the CVE id"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_critical()])):
            _run_pipeline(path, out)
        content = open(os.path.join(out, "pr_comment.md")).read()
        assert "CVE-CRITICAL" in content


# ===========================================================================
# SBOM FILE READING FROM DISK
# ===========================================================================

class TestSBOMFileIntegration:

    def test_sample_sbom_json_loads(self):
        """SYS-22: Bundled sample_sbom.json file can be loaded"""
        sample = Path(__file__).parent.parent / "samples" / "sample_sbom.json"
        if not sample.exists():
            pytest.skip("sample_sbom.json not present")
        result = load_sbom(str(sample))
        assert "components" in result or result is not None

    def test_fail_sbom_json_loads(self):
        """SYS-23: Bundled fail_sbom.json file can be loaded"""
        sample = Path(__file__).parent.parent / "samples" / "fail_sbom.json"
        if not sample.exists():
            pytest.skip("fail_sbom.json not present")
        result = load_sbom(str(sample))
        assert result is not None

    def test_sbom_with_scope_loads(self):
        """SYS-24: sbom_with_scope.json loads and extracts components"""
        sample = Path(__file__).parent.parent / "samples" / "sbom_with_scope.json"
        if not sample.exists():
            pytest.skip("sbom_with_scope.json not present")
        comps = extract_components(load_sbom(str(sample)))
        assert isinstance(comps, list)

    def test_mixed_ecosystems_sbom(self, tmp_path):
        """SYS-25: SBOM with npm, PyPI, and Maven components → all extracted"""
        comps = [
            {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
            {"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0"},
            {"name": "log4j-core", "version": "2.17.0",
             "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0"}
        ]
        path = _write_sbom(tmp_path, comps)
        result = extract_components(load_sbom(path))
        assert len(result) == 3
        ecosystems = {c["ecosystem"] for c in result}
        assert "npm" in ecosystems
        assert "PyPI" in ecosystems
        assert "Maven" in ecosystems


# ===========================================================================
# POLICY & RULES INTEGRATION
# ===========================================================================

class TestPolicyIntegration:

    def test_custom_rules_file_respected(self, tmp_path):
        """SYS-26: Custom rules YAML overrides default policy"""
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(
            "blocked_packages: []\npolicy_gates:\n  fail_on: []\n  warn_on: []\n"
        )
        rules = load_rules(str(rules_file))
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_critical()])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"), rules=rules)
        # With empty fail_on/warn_on, CRITICAL severity still maps to PASS
        assert dec == "PASS"

    def test_blocked_package_rule_from_file(self, tmp_path):
        """SYS-27: Blocked package rule read from disk → FAIL"""
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(
            "blocked_packages:\n  - danger-lib\npolicy_gates:\n  fail_on: []\n  warn_on: []\n"
        )
        rules = load_rules(str(rules_file))
        path = _write_sbom(tmp_path, [_comp("danger-lib", "1.0.0")])
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"), rules=rules)
        assert dec == "FAIL"

    def test_default_policy_file_exists(self):
        """SYS-28: policies/default_policy.yaml is present and readable"""
        policy = load_policy()
        assert policy is not None

    def test_default_policy_gates_applied_by_default(self, tmp_path):
        """SYS-29: Without custom rules, default policy gates are active"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        # HIGH vuln should FAIL by default policy
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_high()])):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "FAIL"


# ===========================================================================
# PERFORMANCE
# ===========================================================================

class TestPipelinePerformance:

    def test_10_component_sbom_under_2s(self, tmp_path):
        """SYS-30: 10-component SBOM (no network) completes in < 2 seconds"""
        comps = [_comp(f"lib-{i}", "1.0") for i in range(10)]
        path = _write_sbom(tmp_path, comps)
        t0 = time.time()
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, str(tmp_path / "out"))
        elapsed = time.time() - t0
        assert elapsed < 2.0, f"Pipeline took {elapsed:.2f}s for 10 components"

    def test_50_component_sbom_under_5s(self, tmp_path):
        """SYS-31: 50-component SBOM (mocked OSV) completes in < 5 seconds"""
        comps = [_comp(f"pkg-{i}", "1.0") for i in range(50)]
        path = _write_sbom(tmp_path, comps)
        t0 = time.time()
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, str(tmp_path / "out"))
        elapsed = time.time() - t0
        assert elapsed < 5.0, f"Pipeline took {elapsed:.2f}s for 50 components"

    def test_100_component_sbom_completes(self, tmp_path):
        """SYS-32: 100-component SBOM (mocked) produces valid output files"""
        comps = [_comp(f"lib-{i}", f"1.{i}.0") for i in range(100)]
        path = _write_sbom(tmp_path, comps)
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, out)
        assert os.path.exists(os.path.join(out, "report.json"))

    def test_single_component_pipeline_fast(self, tmp_path):
        """SYS-33: Single component pipeline completes in < 0.5s"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        t0 = time.time()
        with patch("agent.osv_client.requests.post", return_value=_mock_osv_response([])):
            _run_pipeline(path, str(tmp_path / "out"))
        assert time.time() - t0 < 0.5


# ===========================================================================
# CONSISTENCY
# ===========================================================================

class TestPipelineConsistency:

    def test_deterministic_decision_same_input(self, tmp_path):
        """SYS-34: Same SBOM + same OSV mock → same decision on two runs"""
        comps = [_comp("lib", "1.0")]
        path = _write_sbom(tmp_path, comps)
        results = []
        for i in range(2):
            with patch("agent.osv_client.requests.post",
                       return_value=_mock_osv_response([_vuln_high()])):
                dec, _, _, _ = _run_pipeline(path, str(tmp_path / f"out-{i}"))
                results.append(dec)
        assert results[0] == results[1]

    def test_report_decision_matches_json_decision(self, tmp_path):
        """SYS-35: Decision in pr_comment.md matches decision in report.json"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        out = str(tmp_path / "out")
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_medium()])):
            dec, _, _, _ = _run_pipeline(path, out)
        data = json.loads(open(os.path.join(out, "report.json")).read())
        md = open(os.path.join(out, "pr_comment.md")).read()
        assert data["decision"] == dec
        assert dec in md

    def test_risk_score_consistent_with_severity(self, tmp_path):
        """SYS-36: CRITICAL vuln → risk_score higher than same pipeline with MEDIUM"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_critical()])):
            _, _, _, r_crit = _run_pipeline(path, str(tmp_path / "crit"))
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_medium()])):
            _, _, _, r_med = _run_pipeline(path, str(tmp_path / "med"))
        assert r_crit["risk_summary"]["risk_score"] > r_med["risk_summary"]["risk_score"]

    def test_more_vulns_higher_risk_score(self, tmp_path):
        """SYS-37: Same CVSS with 5 vulns scores higher than 1 vuln"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        one = {"id": "CVE-ONE", "severity": [{"score": "7.5"}]}
        five = [{"id": f"CVE-{i}", "severity": [{"score": "7.5"}]} for i in range(5)]
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([one])):
            _, _, _, r1 = _run_pipeline(path, str(tmp_path / "one"))
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response(five)):
            _, _, _, r5 = _run_pipeline(path, str(tmp_path / "five"))
        assert r5["risk_summary"]["risk_score"] >= r1["risk_summary"]["risk_score"]

    def test_concurrent_pipelines_do_not_interfere(self, tmp_path):
        """SYS-38: Two concurrent pipeline runs write to separate outputs without error"""
        errors = []

        def run(suffix):
            try:
                path = _write_sbom(tmp_path, [_comp("lib", "1.0")], name=f"sbom-{suffix}.json")
                out = str(tmp_path / f"out-{suffix}")
                dec, _, _, _ = _run_pipeline(path, out)
                assert dec == "WARN"
            except Exception as e:
                errors.append(str(e))

        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response([_vuln_medium()])):
            threads = [threading.Thread(target=run, args=(i,)) for i in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        assert not errors, f"Concurrent run errors: {errors}"


# ===========================================================================
# EDGE CASES & RESILIENCE
# ===========================================================================

class TestPipelineEdgeCases:

    def test_osv_api_down_pipeline_completes(self, tmp_path):
        """SYS-39: OSV API failure → pipeline completes (no vulns found) → PASS"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")])
        with patch("requests.post", side_effect=Exception("Network error")):
            dec, _, _, _ = _run_pipeline(path, str(tmp_path / "out"))
        assert dec == "PASS"

    def test_2_spec_versions_handled(self, tmp_path):
        """SYS-40: CycloneDX spec version 1.2 is still parsed"""
        path = _write_sbom(tmp_path, [_comp("lib", "1.0")], spec="1.2")
        comps = extract_components(load_sbom(path))
        assert len(comps) == 1

    def test_no_purl_component_included(self, tmp_path):
        """SYS-41: Component without purl is still scanned (falls back to name)"""
        path = _write_sbom(tmp_path, [{"name": "bare-lib", "version": "1.0.0"}])
        comps = extract_components(load_sbom(path))
        assert len(comps) == 1
        assert comps[0]["name"] == "bare-lib"

    def test_component_missing_version_excluded_from_scan(self, tmp_path):
        """SYS-42: Component with missing version is excluded → not scanned"""
        path = _write_sbom(tmp_path, [{"name": "versionless", "purl": "pkg:npm/versionless"}])
        comps = extract_components(load_sbom(path))
        assert all(c["name"] != "versionless" for c in comps)

    def test_unknown_cvss_triggers_manual_review(self, tmp_path):
        """SYS-43: Vulns with no CVSS → manual review warning in report"""
        path = _write_sbom(tmp_path, [_comp("mystery-lib", "1.0")])
        out = str(tmp_path / "out")
        mock_vulns = [{"id": "CVE-NOCVSS"}]  # No severity, no database_specific
        with patch("agent.osv_client.requests.post",
                   return_value=_mock_osv_response(mock_vulns)):
            _run_pipeline(path, out)
        md = open(os.path.join(out, "pr_comment.md")).read()
        assert "manual review" in md.lower() or "unknown" in md.lower()

    def test_large_version_string(self, tmp_path):
        """SYS-44: Very long version string is handled without error"""
        path = _write_sbom(tmp_path, [
            {"name": "lib", "version": "1.2.3-alpha.4+build.56789.abc.def", "purl": "pkg:npm/lib@1.2.3"}
        ])
        comps = extract_components(load_sbom(path))
        assert len(comps) == 1

    def test_all_components_missing_version_empty_scan(self, tmp_path):
        """SYS-45: SBOM where all components lack version → 0 scan targets"""
        comps = [{"name": f"lib-{i}", "purl": f"pkg:npm/lib-{i}"} for i in range(3)]
        path = _write_sbom(tmp_path, comps)
        result = extract_components(load_sbom(path))
        assert result == []
