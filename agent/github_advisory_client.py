"""
GitHub Advisory Database Client

Official GitHub Advisory Database: https://github.com/advisories
GraphQL API: https://docs.github.com/en/graphql/reference/queries#securityadvisory
REST API: https://api.github.com/advisories

Note: GitHub Advisory Database is free and doesn't require authentication for public advisories
"""

import requests
from typing import List, Dict, Any, Optional


GITHUB_ADVISORY_API = "https://api.github.com/advisories"


def normalize_ecosystem(ecosystem: str) -> str:
    """
    Normalize ecosystem name to GitHub Advisory format.
    
    GitHub uses: npm, pip, maven, nuget, rubygems, composer, go, rust
    """
    ecosystem_map = {
        "npm": "npm",
        "PyPI": "pip",
        "Maven": "maven",
        "Go": "go",
        "NuGet": "nuget",
        "RubyGems": "rubygems",
        "Packagist": "composer",
        "Cargo": "rust"
    }
    
    return ecosystem_map.get(ecosystem, ecosystem.lower() if ecosystem else "")


def query_github_advisory(package_name: str, version: str, ecosystem: str = None) -> List[Dict[str, Any]]:
    """
    Query GitHub Advisory Database for vulnerabilities.
    
    Args:
        package_name: Name of the package (e.g., "lodash", "log4j-core")
        version: Version of the package
        ecosystem: Optional ecosystem (npm, PyPI, Maven, etc.)
    
    Returns:
        List of vulnerability dictionaries with standardized format
    """
    
    vulnerabilities = []
    
    try:
        # GitHub Advisory API doesn't support version-specific queries directly
        # We need to query by package and then filter by affected versions
        
        params = {
            "per_page": 100  # Get up to 100 advisories
        }
        
        # Add ecosystem filter if provided
        if ecosystem:
            gh_ecosystem = normalize_ecosystem(ecosystem)
            if gh_ecosystem:
                params["ecosystem"] = gh_ecosystem
        
        # GitHub Advisory API uses package name in the query
        # Format: ?affects=package:ecosystem/package-name
        if ecosystem:
            gh_ecosystem = normalize_ecosystem(ecosystem)
            if gh_ecosystem:
                # Use the affects parameter for more precise results
                params["affects"] = f"{gh_ecosystem}/{package_name}"
        
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        response = requests.get(GITHUB_ADVISORY_API, params=params, headers=headers, timeout=10)
        
        if response.status_code == 200:
            advisories = response.json()
            
            for advisory in advisories:
                ghsa_id = advisory.get("ghsa_id", "UNKNOWN")
                cve_id = advisory.get("cve_id")
                
                # Extract CVSS score
                cvss_score = None
                cvss_data = advisory.get("cvss", {})
                if cvss_data:
                    cvss_score = cvss_data.get("score")
                
                # Get severity
                severity = advisory.get("severity", "UNKNOWN").upper()
                
                # If no CVSS, map severity to approximate score
                if cvss_score is None and severity:
                    severity_map = {
                        "CRITICAL": 9.5,
                        "HIGH": 7.5,
                        "MODERATE": 5.0,
                        "MEDIUM": 5.0,
                        "LOW": 2.5
                    }
                    cvss_score = severity_map.get(severity)
                
                # Extract summary and description
                summary = advisory.get("summary", "")
                description = advisory.get("description", "")
                
                # Check if this advisory affects the specific version
                affects_this_version = False
                affected_versions = []
                
                vulnerabilities_data = advisory.get("vulnerabilities", [])
                for vuln_data in vulnerabilities_data:
                    pkg = vuln_data.get("package", {})
                    pkg_ecosystem = pkg.get("ecosystem", "").lower()
                    pkg_name = pkg.get("name", "").lower()
                    
                    # Check if package name matches
                    if pkg_name == package_name.lower():
                        # Check vulnerable version ranges
                        vulnerable_version_range = vuln_data.get("vulnerable_version_range", "")
                        affected_versions.append(vulnerable_version_range)
                        
                        # Simple version check (this is a heuristic - proper semver comparison would be better)
                        # For now, we'll assume if the package name matches, it might be affected
                        affects_this_version = True
                
                # Only include if it affects this package
                if affects_this_version or not vulnerabilities_data:
                    vuln = {
                        "id": cve_id if cve_id else ghsa_id,
                        "ghsa_id": ghsa_id,
                        "cve_id": cve_id,
                        "source": "GitHub Advisory",
                        "package": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "cvss": cvss_score,
                        "severity": severity,
                        "summary": summary,
                        "description": description,
                        "affected_versions": affected_versions,
                        "published": advisory.get("published_at", ""),
                        "updated": advisory.get("updated_at", ""),
                        "url": advisory.get("html_url", ""),
                        "raw_data": advisory
                    }
                    
                    vulnerabilities.append(vuln)
        
        elif response.status_code == 404:
            # No advisories found - this is normal, not an error
            pass
        else:
            print(f"⚠️  GitHub Advisory API returned status {response.status_code} for {package_name}")
    
    except requests.exceptions.Timeout:
        print(f"⚠️  GitHub Advisory API timeout for {package_name} - skipping")
    except Exception as e:
        print(f"⚠️  GitHub Advisory query failed for {package_name}: {str(e)}")
    
    return vulnerabilities


def get_advisory_details(ghsa_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed information for a specific GHSA advisory.
    
    Args:
        ghsa_id: GitHub Security Advisory ID (e.g., "GHSA-xxxx-xxxx-xxxx")
    
    Returns:
        Dictionary with advisory details or None if not found
    """
    
    try:
        url = f"{GITHUB_ADVISORY_API}/{ghsa_id}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            advisory = response.json()
            
            cvss_score = None
            cvss_data = advisory.get("cvss", {})
            if cvss_data:
                cvss_score = cvss_data.get("score")
            
            return {
                "id": advisory.get("ghsa_id"),
                "cve_id": advisory.get("cve_id"),
                "source": "GitHub Advisory",
                "cvss": cvss_score,
                "severity": advisory.get("severity"),
                "raw_data": advisory
            }
    
    except Exception as e:
        print(f"⚠️  Failed to get GitHub Advisory details for {ghsa_id}: {str(e)}")
    
    return None
