"""
Pytest configuration and fixtures for PRISM tests
"""
import pytest
import tempfile
import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def sample_sbom():
    """Generate a sample CycloneDX SBOM for testing"""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "component": {
                "name": "test-app",
                "version": "1.0.0",
                "type": "application"
            }
        },
        "components": [
            {
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
                "type": "library"
            },
            {
                "name": "axios",
                "version": "0.21.0",
                "purl": "pkg:npm/axios@0.21.0",
                "type": "library"
            },
            {
                "name": "express",
                "version": "4.17.0",
                "purl": "pkg:npm/express@4.17.0",
                "type": "library"
            }
        ]
    }


@pytest.fixture
def vulnerable_sbom():
    """SBOM with known vulnerable packages"""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "name": "lodash",
                "version": "4.17.15",  # Known vulnerable version
                "purl": "pkg:npm/lodash@4.17.15",
                "type": "library"
            },
            {
                "name": "minimist",
                "version": "1.2.0",  # Known vulnerable
                "purl": "pkg:npm/minimist@1.2.0",
                "type": "library"
            }
        ]
    }


@pytest.fixture
def safe_sbom():
    """SBOM with no known vulnerabilities"""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "name": "lodash",
                "version": "4.17.21",  # Latest safe version
                "purl": "pkg:npm/lodash@4.17.21",
                "type": "library"
            }
        ]
    }


@pytest.fixture
def temp_sbom_file(tmp_path, sample_sbom):
    """Create a temporary SBOM file"""
    sbom_file = tmp_path / "test_sbom.json"
    with open(sbom_file, 'w') as f:
        json.dump(sample_sbom, f, indent=2)
    return sbom_file


@pytest.fixture
def temp_project_root(tmp_path):
    """Create a temporary project directory for pipeline and output testing"""
    project_root = tmp_path / "test_project"
    project_root.mkdir()
    return project_root


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create temporary output directory"""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


# ============================================================================
# Mock API Response Fixtures
# ============================================================================

@pytest.fixture
def mock_osv_response():
    """Mock OSV API response"""
    return {
        "vulns": [
            {
                "id": "GHSA-35jh-r3h4-6jhm",
                "summary": "Prototype Pollution in lodash",
                "details": "Vulnerable to prototype pollution via template.",
                "aliases": ["CVE-2021-23337"],
                "modified": "2021-02-15T00:00:00Z",
                "published": "2021-02-15T00:00:00Z",
                "database_specific": {
                    "severity": "HIGH",
                    "cvss_score": 7.4
                },
                "affected": [
                    {
                        "package": {
                            "name": "lodash",
                            "ecosystem": "npm"
                        },
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "4.17.21"}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }


# ============================================================================
# Performance Tracking Fixtures
# ============================================================================

@pytest.fixture
def performance_tracker():
    """Track performance metrics during tests"""
    class PerformanceTracker:
        def __init__(self):
            self.metrics = {}

        def start(self, name):
            import time
            self.metrics[name] = {"start": time.time()}

        def stop(self, name):
            import time
            if name in self.metrics:
                self.metrics[name]["end"] = time.time()
                self.metrics[name]["duration"] = (
                    self.metrics[name]["end"] - self.metrics[name]["start"]
                )

        def get_duration(self, name):
            if name in self.metrics and "duration" in self.metrics[name]:
                return self.metrics[name]["duration"]
            return None

        def get_all_metrics(self):
            return self.metrics

    return PerformanceTracker()


@pytest.fixture
def metrics_collector():
    """Collect test metrics for reporting"""
    class MetricsCollector:
        def __init__(self):
            self.results = []

        def add_result(self, test_name, metric_name, value, expected=None):
            self.results.append({
                "test_name": test_name,
                "metric": metric_name,
                "value": value,
                "expected": expected,
                "timestamp": datetime.utcnow().isoformat()
            })

        def record(self, metric_name, value):
            """Shorthand: record a metric without a test name context"""
            self.results.append({
                "test_name": "general",
                "metric": metric_name,
                "value": value,
                "expected": None,
                "timestamp": datetime.utcnow().isoformat()
            })

        def get_results(self):
            return self.results

        def save_to_json(self, filepath):
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)

    return MetricsCollector()


# ============================================================================
# Cleanup
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_output_files():
    """Cleanup generated output files after tests"""
    yield
    # Cleanup happens after test
    output_dir = Path(__file__).parent.parent / "output"
    if output_dir.exists():
        for file in output_dir.glob("test_*"):
            try:
                file.unlink()
            except:
                pass
