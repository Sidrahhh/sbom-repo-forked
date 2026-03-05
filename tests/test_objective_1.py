"""
PRISM - Objective 1 Test Suite
================================
Objective 1: Automated SBOM Generation & OSV Vulnerability Scanning

Covers:
  Part A - SBOM Parser  : CycloneDX loading, component extraction, purl decoding
  Part B - OSV Client   : API querying, CVSS extraction, error handling

Test IDs use the format  OBJ1-<PART>-<NN>
"""

import json
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.sbom_parser import load_sbom, extract_components, parse_purl
from agent.osv_client import query_osv


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_sbom(tmp_path, components, spec="1.4"):
    data = {"bomFormat": "CycloneDX", "specVersion": spec, "components": components}
    f = tmp_path / "sbom.json"
    f.write_text(json.dumps(data))
    return str(f)


def _comp(name, version, purl=None):
    c = {"name": name, "version": version}
    if purl:
        c["purl"] = purl
    return c


# ===========================================================================
# PART A — SBOM PARSER
# ===========================================================================

class TestSBOMParserLoading:
    """OBJ1-A: File loading and basic extraction"""

    def test_load_valid_json_file(self, tmp_path):
        """OBJ1-A-01: load_sbom reads valid CycloneDX file correctly"""
        path = _write_sbom(tmp_path, [_comp("lodash", "4.17.15", "pkg:npm/lodash@4.17.15")])
        result = load_sbom(path)
        assert result["bomFormat"] == "CycloneDX"

    def test_load_spec_version_1_3(self, tmp_path):
        """OBJ1-A-02: specVersion 1.3 is accepted"""
        path = _write_sbom(tmp_path, [], spec="1.3")
        result = load_sbom(path)
        assert result["specVersion"] == "1.3"

    def test_load_spec_version_1_5(self, tmp_path):
        """OBJ1-A-03: specVersion 1.5 is accepted"""
        path = _write_sbom(tmp_path, [], spec="1.5")
        assert load_sbom(path)["specVersion"] == "1.5"

    def test_load_missing_file_raises(self, tmp_path):
        """OBJ1-A-04: Missing file raises an exception"""
        with pytest.raises(Exception):
            load_sbom(str(tmp_path / "nonexistent.json"))

    def test_load_invalid_json_raises(self, tmp_path):
        """OBJ1-A-05: Invalid JSON raises an exception"""
        f = tmp_path / "bad.json"
        f.write_text("{ this is not json }")
        with pytest.raises(Exception):
            load_sbom(str(f))

    def test_extract_empty_components(self, tmp_path):
        """OBJ1-A-06: Empty components list → []"""
        path = _write_sbom(tmp_path, [])
        assert extract_components(load_sbom(path)) == []

    def test_extract_missing_components_key(self, tmp_path):
        """OBJ1-A-07: SBOM with no 'components' key → []"""
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4"}))
        assert extract_components(load_sbom(str(f))) == []

    def test_extract_single_component(self, tmp_path):
        """OBJ1-A-08: One component is extracted correctly"""
        path = _write_sbom(tmp_path, [_comp("requests", "2.28.0", "pkg:pypi/requests@2.28.0")])
        comps = extract_components(load_sbom(path))
        assert len(comps) == 1
        assert comps[0]["name"] == "requests"

    def test_extract_five_components(self, tmp_path):
        """OBJ1-A-09: Five components all extracted"""
        pkgs = [_comp(f"lib-{i}", f"1.{i}.0", f"pkg:npm/lib-{i}@1.{i}.0") for i in range(5)]
        path = _write_sbom(tmp_path, pkgs)
        assert len(extract_components(load_sbom(path))) == 5

    def test_extract_100_components_stress(self, tmp_path):
        """OBJ1-A-10: 100 components extracted (stress)"""
        pkgs = [_comp(f"pkg-{i}", f"0.{i}.0", f"pkg:npm/pkg-{i}@0.{i}.0") for i in range(100)]
        path = _write_sbom(tmp_path, pkgs)
        comps = extract_components(load_sbom(path))
        assert len(comps) == 100

    def test_extra_fields_ignored(self, tmp_path):
        """OBJ1-A-11: Extra fields on a component are silently ignored"""
        c = _comp("lodash", "4.17.15", "pkg:npm/lodash@4.17.15")
        c["description"] = "A utility library"
        c["licenses"] = [{"license": {"id": "MIT"}}]
        path = _write_sbom(tmp_path, [c])
        comps = extract_components(load_sbom(path))
        assert comps[0]["name"] == "lodash"

    def test_component_missing_version_excluded(self, tmp_path):
        """OBJ1-A-12: Component with no version is excluded from output"""
        path = _write_sbom(tmp_path, [{"name": "no-version-lib", "purl": "pkg:npm/no-version-lib"}])
        comps = extract_components(load_sbom(path))
        assert len(comps) == 0

    def test_component_no_purl_uses_name(self, tmp_path):
        """OBJ1-A-13: No purl → component name used as-is"""
        path = _write_sbom(tmp_path, [_comp("plain-lib", "1.0.0")])
        comps = extract_components(load_sbom(path))
        assert comps[0]["name"] == "plain-lib"
        assert comps[0]["ecosystem"] is None

    def test_unicode_package_name(self, tmp_path):
        """OBJ1-A-14: Unicode characters in package name are handled"""
        path = _write_sbom(tmp_path, [_comp("日本語-pkg", "1.0.0")])
        comps = extract_components(load_sbom(path))
        assert comps[0]["name"] == "日本語-pkg"

    def test_prerelease_version_retained(self, tmp_path):
        """OBJ1-A-15: Pre-release version string kept intact"""
        path = _write_sbom(tmp_path, [_comp("alpha-lib", "1.0.0-beta.1", "pkg:npm/alpha-lib@1.0.0-beta.1")])
        comps = extract_components(load_sbom(path))
        assert comps[0]["version"] == "1.0.0-beta.1"

    def test_numeric_only_version(self, tmp_path):
        """OBJ1-A-16: Plain numeric version (e.g. '4') is kept"""
        path = _write_sbom(tmp_path, [_comp("old-lib", "4")])
        comps = extract_components(load_sbom(path))
        assert comps[0]["version"] == "4"


class TestPurlParsing:
    """OBJ1-B: purl ecosystem and name extraction"""

    def test_purl_npm(self):
        """OBJ1-B-01: pkg:npm/lodash@4.17.15 → npm ecosystem"""
        eco, name = parse_purl("pkg:npm/lodash@4.17.15")
        assert eco == "npm"
        assert name == "lodash"

    def test_purl_pypi(self):
        """OBJ1-B-02: pkg:pypi/requests@2.28.0 → PyPI ecosystem"""
        eco, name = parse_purl("pkg:pypi/requests@2.28.0")
        assert eco == "PyPI"
        assert name == "requests"

    def test_purl_maven(self):
        """OBJ1-B-03: Maven purl → namespace:name format"""
        eco, name = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        assert eco == "Maven"
        assert "log4j-core" in name

    def test_purl_golang(self):
        """OBJ1-B-04: pkg:golang/... → Go ecosystem"""
        eco, name = parse_purl("pkg:golang/github.com/gin-gonic/gin@1.7.0")
        assert eco == "Go"

    def test_purl_nuget(self):
        """OBJ1-B-05: pkg:nuget/Newtonsoft.Json@13.0.1 → NuGet"""
        eco, name = parse_purl("pkg:nuget/Newtonsoft.Json@13.0.1")
        assert eco == "NuGet"
        assert name == "Newtonsoft.Json"

    def test_purl_rubygems(self):
        """OBJ1-B-06: pkg:rubygems/rails@6.1.0 → RubyGems"""
        eco, name = parse_purl("pkg:rubygems/rails@6.1.0")
        assert eco == "RubyGems"
        assert name == "rails"

    def test_purl_unknown_ecosystem(self):
        """OBJ1-B-07: Unknown ecosystem type → ecosystem is None"""
        eco, name = parse_purl("pkg:custom/somelib@1.0.0")
        assert eco is None

    def test_purl_malformed_returns_none(self):
        """OBJ1-B-08: Completely malformed purl → (None, None)"""
        eco, name = parse_purl("not-a-purl-at-all")
        assert eco is None

    def test_purl_empty_string(self):
        """OBJ1-B-09: Empty purl → (None, None)"""
        eco, name = parse_purl("")
        assert eco is None

    def test_purl_scoped_npm_package(self, tmp_path):
        """OBJ1-B-10: Scoped npm package (@scope/name) included in SBOM"""
        path = _write_sbom(tmp_path, [_comp("@angular/core", "14.0.0", "pkg:npm/%40angular/core@14.0.0")])
        comps = extract_components(load_sbom(path))
        assert len(comps) == 1


# ===========================================================================
# PART C — OSV Client
# ===========================================================================

class TestOSVClientSuccess:
    """OBJ1-C: Successful OSV API response scenarios"""

    def test_vuln_with_severity_array_cvss(self):
        """OBJ1-C-01: CVSS extracted from severity array"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "CVE-2021-23337",
            "severity": [{"type": "CVSS_V3", "score": "8.1"}]
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("lodash", "4.17.15", "npm")
        assert len(vulns) == 1
        assert vulns[0]["cvss"] == 8.1

    def test_vuln_cvss_from_database_specific_high(self):
        """OBJ1-C-02: CVSS derived from database_specific.severity = HIGH"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "GHSA-xxxx",
            "database_specific": {"severity": "HIGH"}
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("express", "4.17.0", "npm")
        assert vulns[0]["cvss"] == 7.5

    def test_vuln_cvss_from_database_specific_critical(self):
        """OBJ1-C-03: CVSS derived from database_specific.severity = CRITICAL"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "CVE-2021-99999",
            "database_specific": {"severity": "CRITICAL"}
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("malicious-pkg", "1.0.0", "npm")
        assert vulns[0]["cvss"] == 9.5

    def test_vuln_cvss_from_database_specific_medium(self):
        """OBJ1-C-04: database_specific.severity = MEDIUM → 5.0"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "CVE-2022-11111",
            "database_specific": {"severity": "MEDIUM"}
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("some-pkg", "2.0.0")
        assert vulns[0]["cvss"] == 5.0

    def test_vuln_cvss_from_database_specific_low(self):
        """OBJ1-C-05: database_specific.severity = LOW → 2.5"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "CVE-2022-22222",
            "database_specific": {"severity": "LOW"}
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("minor-pkg", "1.0.1")
        assert vulns[0]["cvss"] == 2.5

    def test_no_cvss_gets_zero(self):
        """OBJ1-C-06: Vuln with no CVSS info → cvss = 0.0"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{"id": "CVE-????"}]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("unknown-severity-pkg", "1.0.0")
        assert vulns[0]["cvss"] == 0.0

    def test_has_cvss_flag_true_when_cvss_present(self):
        """OBJ1-C-07: has_cvss = True when score > 0"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "CVE-1111",
            "severity": [{"score": "7.8"}]
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("high-pkg", "1.0.0")
        assert vulns[0]["has_cvss"] is True

    def test_has_cvss_flag_false_when_no_cvss(self):
        """OBJ1-C-08: has_cvss = False when score = 0.0"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{"id": "CVE-UNKNOWN"}]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("no-cvss-pkg", "1.0.0")
        assert vulns[0]["has_cvss"] is False

    def test_multiple_vulns_same_package(self):
        """OBJ1-C-09: Multiple vulns in response all returned"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [
            {"id": "CVE-A", "severity": [{"score": "9.1"}]},
            {"id": "CVE-B", "severity": [{"score": "7.2"}]},
            {"id": "CVE-C", "database_specific": {"severity": "MEDIUM"}},
        ]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("multi-vuln-pkg", "2.0.0", "npm")
        assert len(vulns) == 3
        ids = {v["id"] for v in vulns}
        assert ids == {"CVE-A", "CVE-B", "CVE-C"}

    def test_first_severity_entry_used(self):
        """OBJ1-C-10: First entry in severity array is used for CVSS"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "CVE-FIRST",
            "severity": [
                {"type": "CVSS_V3", "score": "9.8"},
                {"type": "CVSS_V2", "score": "5.0"}
            ]
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("some-lib", "1.0.0")
        assert vulns[0]["cvss"] == 9.8

    def test_empty_vulns_response(self):
        """OBJ1-C-11: Response with vulns:[] → returns []"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": []}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("safe-pkg", "1.0.0", "npm")
        assert vulns == []

    def test_no_vulns_key_in_response(self):
        """OBJ1-C-12: Response without 'vulns' key → returns []"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("clean-pkg", "2.0.0")
        assert vulns == []

    def test_vuln_source_is_osv(self):
        """OBJ1-C-13: source field is always 'OSV'"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{"id": "GHSA-0000"}]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("any-pkg", "1.0.0")
        assert vulns[0]["source"] == "OSV"

    def test_vuln_raw_data_included(self):
        """OBJ1-C-14: raw_data is attached for remediation use"""
        raw = {"id": "CVE-RAW", "affected": []}
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [raw]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("raw-pkg", "3.0.0")
        assert vulns[0]["raw_data"] == raw

    def test_ecosystem_included_in_payload(self):
        """OBJ1-C-15: Ecosystem is passed in POST payload when provided"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": []}
        with patch("requests.post", return_value=mock_resp) as mock_post:
            query_osv("lodash", "4.17.15", "npm")
        payload = mock_post.call_args[1]["json"]
        assert payload["package"]["ecosystem"] == "npm"

    def test_no_ecosystem_omits_field(self):
        """OBJ1-C-16: No ecosystem → 'ecosystem' key absent from payload"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": []}
        with patch("requests.post", return_value=mock_resp) as mock_post:
            query_osv("some-pkg", "1.0.0", None)
        payload = mock_post.call_args[1]["json"]
        assert "ecosystem" not in payload["package"]


class TestOSVClientErrors:
    """OBJ1-D: Error handling and resilience"""

    def test_timeout_returns_empty(self):
        """OBJ1-D-01: Timeout exception → returns []"""
        with patch("requests.post", side_effect=Exception("Timeout")):
            assert query_osv("some-lib", "1.0.0") == []

    def test_connection_error_returns_empty(self):
        """OBJ1-D-02: ConnectionError → returns []"""
        import requests as req
        with patch("requests.post", side_effect=req.exceptions.ConnectionError("No network")):
            assert query_osv("lib", "1.0.0") == []

    def test_http_500_returns_empty(self):
        """OBJ1-D-03: HTTP 500 → raise_for_status fires → returns []"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("500 Server Error")
        with patch("requests.post", return_value=mock_resp):
            assert query_osv("lib", "1.0.0") == []

    def test_http_404_returns_empty(self):
        """OBJ1-D-04: HTTP 404 raises → returns []"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("404 Not Found")
        with patch("requests.post", return_value=mock_resp):
            assert query_osv("unknown-lib", "9.9.9") == []

    def test_http_429_rate_limit_returns_empty(self):
        """OBJ1-D-05: HTTP 429 (rate limit) → returns []"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("429 Too Many Requests")
        with patch("requests.post", return_value=mock_resp):
            assert query_osv("busy-lib", "1.0.0") == []

    def test_malformed_json_response_returns_empty(self):
        """OBJ1-D-06: API returns non-JSON → returns []"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.side_effect = ValueError("No JSON")
        with patch("requests.post", return_value=mock_resp):
            assert query_osv("bad-json-lib", "1.0.0") == []

    def test_severity_score_not_a_float(self):
        """OBJ1-D-07: Non-numeric severity score → falls through to database_specific or 0.0"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "CVE-NAN",
            "severity": [{"score": "N/A"}]
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("weird-lib", "1.0.0")
        assert vulns[0]["cvss"] == 0.0

    def test_database_specific_unknown_severity(self):
        """OBJ1-D-08: database_specific.severity = UNKNOWN → 0.0"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [{
            "id": "CVE-UNKSEV",
            "database_specific": {"severity": "UNKNOWN"}
        }]}
        with patch("requests.post", return_value=mock_resp):
            vulns = query_osv("mystery-lib", "1.0.0")
        assert vulns[0]["cvss"] == 0.0
