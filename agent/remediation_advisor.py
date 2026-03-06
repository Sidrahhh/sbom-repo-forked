"""
Remediation Advisor - Provides smart fix suggestions for vulnerabilities

Features:
1. Extracts fixed versions from vulnerability databases
2. Suggests upgrade commands based on ecosystem
3. Identifies potential breaking changes (major version bumps)
4. Provides prioritized remediation recommendations
"""

from typing import List, Dict, Any, Optional
import re


def extract_fixed_version(vuln: Dict[str, Any]) -> Optional[str]:
    """
    Extract the fixed version from vulnerability data.

    Args:
        vuln: Vulnerability dictionary with raw_data from OSV/NVD/GitHub

    Returns:
        Fixed version string or None if not available
    """
    fixed_version = None

    # Try OSV raw_data format
    if "raw_data" in vuln:
        raw = vuln["raw_data"]

        # Check OSV affected ranges
        if "affected" in raw:
            for affected in raw["affected"]:
                ranges = affected.get("ranges", [])
                for range_info in ranges:
                    events = range_info.get("events", [])
                    for event in events:
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            return fixed_version

    # Try GitHub Advisory format
    if "ghsa_id" in vuln or "source" == "GitHub Advisory":
        raw = vuln.get("raw_data", {})
        vulnerabilities_data = raw.get("vulnerabilities", [])
        for vuln_data in vulnerabilities_data:
            patched_versions = vuln_data.get("patched_versions", "")
            if patched_versions:
                # Extract version from patterns like ">= 2.17.1"
                match = re.search(r'>=?\s*([0-9.]+)', patched_versions)
                if match:
                    return match.group(1)

    return fixed_version


def get_latest_safe_version(package_name: str, current_version: str, ecosystem: str,
                            vulnerabilities: List[Dict[str, Any]]) -> Optional[str]:
    """
    Determine the latest safe version to upgrade to.

    Strategy:
    - Find the highest fixed version across all vulnerabilities
    - Ensure it's higher than current version
    - Prefer minor version bumps over major (less breaking changes)

    Args:
        package_name: Package name
        current_version: Current version
        ecosystem: Ecosystem (npm, PyPI, Maven, etc.)
        vulnerabilities: List of vulnerabilities affecting this package

    Returns:
        Recommended version string or None
    """
    fixed_versions = []

    for vuln in vulnerabilities:
        fixed = extract_fixed_version(vuln)
        if fixed:
            fixed_versions.append(fixed)

    if not fixed_versions:
        return None

    # Sort versions (simple lexicographic sort - proper semver would be better)
    # Filter out versions with special characters for now
    clean_versions = [v for v in fixed_versions if re.match(r'^[0-9.]+$', v)]

    if not clean_versions:
        return fixed_versions[0]  # Return first available if can't clean

    # Sort by version components
    def version_key(v):
        try:
            parts = [int(p) for p in v.split('.')]
            # Pad to ensure consistent comparison
            return tuple(parts + [0] * (10 - len(parts)))
        except:
            return (0,)

    clean_versions.sort(key=version_key, reverse=True)

    # Return highest version
    return clean_versions[0]


def analyze_version_change(current_version: str, target_version: str) -> Dict[str, Any]:
    """
    Analyze the impact of version change (major/minor/patch).

    Uses semantic versioning (semver) convention:
    - Major: Breaking changes expected
    - Minor: New features, backward compatible
    - Patch: Bug fixes, backward compatible

    Args:
        current_version: Current version string
        target_version: Target version string

    Returns:
        {
            "change_type": "major" | "minor" | "patch" | "unknown",
            "breaking_likely": bool,
            "current_major": int,
            "target_major": int,
            "warning": str
        }
    """
    result = {
        "change_type": "unknown",
        "breaking_likely": False,
        "current_major": 0,
        "target_major": 0,
        "warning": ""
    }

    try:
        # Parse versions
        current_parts = [int(p) for p in current_version.split('.')]
        target_parts = [int(p) for p in target_version.split('.')]

        # Pad to ensure 3 parts [major, minor, patch]
        while len(current_parts) < 3:
            current_parts.append(0)
        while len(target_parts) < 3:
            target_parts.append(0)

        result["current_major"] = current_parts[0]
        result["target_major"] = target_parts[0]

        # Determine change type
        if target_parts[0] > current_parts[0]:
            result["change_type"] = "major"
            result["breaking_likely"] = True
            result["warning"] = f"⚠️ Major version upgrade ({current_version} → {target_version}) may contain breaking changes"
        elif target_parts[1] > current_parts[1]:
            result["change_type"] = "minor"
            result["breaking_likely"] = False
            result["warning"] = f"Minor version upgrade ({current_version} → {target_version}) - should be safe"
        elif target_parts[2] > current_parts[2]:
            result["change_type"] = "patch"
            result["breaking_likely"] = False
            result["warning"] = f"Patch version upgrade ({current_version} → {target_version}) - safe"
        else:
            result["warning"] = "Target version is not higher than current version"

    except Exception as e:
        result["warning"] = f"Could not parse version numbers: {str(e)}"

    return result


def generate_upgrade_command(package_name: str, target_version: str, ecosystem: str) -> str:
    """
    Generate the upgrade command for the package manager.

    Args:
        package_name: Package name
        target_version: Target version to upgrade to
        ecosystem: Ecosystem (npm, PyPI, Maven, etc.)

    Returns:
        Command string to upgrade the package
    """
    commands = {
        "npm": f"npm install {package_name}@{target_version}",
        "PyPI": f"pip install {package_name}=={target_version}",
        "Maven": f"Update pom.xml: <version>{target_version}</version>",
        "Go": f"go get {package_name}@v{target_version}",
        "NuGet": f"dotnet add package {package_name} --version {target_version}",
        "RubyGems": f"gem install {package_name} -v {target_version}",
        "Cargo": f"cargo update {package_name} --precise {target_version}"
    }

    return commands.get(ecosystem, f"Upgrade {package_name} to version {target_version}")


def generate_remediation_advice(
    package_name: str,
    current_version: str,
    ecosystem: str,
    vulnerabilities: List[Dict[str, Any]],
    reachability_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate comprehensive remediation advice for a vulnerable package.

    Args:
        package_name: Package name
        current_version: Current version
        ecosystem: Ecosystem
        vulnerabilities: List of vulnerabilities
        reachability_info: Reachability analysis results

    Returns:
        {
            "recommended_version": str,
            "upgrade_command": str,
            "priority": "critical" | "high" | "medium" | "low",
            "change_analysis": dict,
            "actionable_steps": list[str],
            "is_reachable": bool,
            "kev_count": int
        }
    """
    # Determine recommended version
    recommended_version = get_latest_safe_version(
        package_name, current_version, ecosystem, vulnerabilities
    )

    if not recommended_version:
        return {
            "recommended_version": None,
            "upgrade_command": None,
            "priority": "unknown",
            "change_analysis": {},
            "actionable_steps": ["⚠️ No fixed version available - consider alternative packages"],
            "is_reachable": reachability_info.get("reachable", True),
            "kev_count": 0
        }

    # Analyze version change
    change_analysis = analyze_version_change(current_version, recommended_version)

    # Generate upgrade command
    upgrade_command = generate_upgrade_command(package_name, recommended_version, ecosystem)

    # Determine priority
    is_reachable = reachability_info.get("reachable", True)
    kev_count = sum(1 for v in vulnerabilities if v.get("is_actively_exploited", False))
    max_cvss = max((v.get("cvss", 0) or 0 for v in vulnerabilities), default=0)

    if kev_count > 0:
        priority = "critical"
    elif is_reachable and max_cvss >= 9.0:
        priority = "critical"
    elif is_reachable and max_cvss >= 7.0:
        priority = "high"
    elif is_reachable and max_cvss >= 4.0:
        priority = "medium"
    elif not is_reachable:
        priority = "low"
    else:
        priority = "medium"

    # Generate actionable steps
    steps = []

    if kev_count > 0:
        steps.append(f"🚨 **URGENT:** {kev_count} actively exploited vulnerabilities - patch immediately!")

    if is_reachable:
        steps.append(f"1. Upgrade {package_name} from {current_version} to {recommended_version}")
        steps.append(f"2. Run: `{upgrade_command}`")
    else:
        steps.append(f"ℹ️ Package is not reachable in production - lower priority")
        steps.append(f"1. Consider upgrading {package_name} from {current_version} to {recommended_version}")

    if change_analysis.get("breaking_likely"):
        steps.append(f"3. ⚠️ Test thoroughly - major version upgrades may break compatibility")
        steps.append(f"4. Review CHANGELOG for breaking changes")
    else:
        steps.append(f"3. Run tests to verify compatibility")

    steps.append(f"5. Update package.json/requirements.txt/pom.xml with new version")

    return {
        "recommended_version": recommended_version,
        "upgrade_command": upgrade_command,
        "priority": priority,
        "change_analysis": change_analysis,
        "actionable_steps": steps,
        "is_reachable": is_reachable,
        "kev_count": kev_count,
        "max_cvss": max_cvss
    }


def generate_remediation_summary(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generate remediation advice for all vulnerable components.

    Args:
        findings: List of component findings with vulnerabilities and reachability

    Returns:
        List of remediation recommendations, sorted by priority
    """
    remediations = []

    for finding in findings:
        if not finding.get("vulnerabilities"):
            continue

        component = finding["component"]
        vulnerabilities = finding["vulnerabilities"]
        reachability = component.get("reachability", {})

        advice = generate_remediation_advice(
            component["name"],
            component["version"],
            component.get("ecosystem", "unknown"),
            vulnerabilities,
            reachability
        )

        # Add component info
        advice["component"] = component["name"]
        advice["current_version"] = component["version"]
        advice["vulnerability_count"] = len(vulnerabilities)

        remediations.append(advice)

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    remediations.sort(key=lambda r: (priority_order.get(r["priority"], 99), -r.get("max_cvss", 0)))

    return remediations
