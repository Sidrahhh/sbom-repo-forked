"""
NVD (National Vulnerability Database) API Client

Official NVD API v2.0: https://nvd.nist.gov/developers/vulnerabilities
Rate Limits: 5 requests per 30 seconds (without API key)
"""

import requests
import time
from typing import List, Dict, Any, Optional


# NVD API endpoint
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(package_name: str, version: str, ecosystem: str = None) -> List[Dict[str, Any]]:
    """
    Query NVD for vulnerabilities affecting a specific package.
    
    Note: NVD uses CPE (Common Platform Enumeration) format, which doesn't
    map 1:1 to package names. This implementation searches by keyword.
    
    Args:
        package_name: Name of the package (e.g., "log4j-core", "lodash")
        version: Version of the package
        ecosystem: Optional ecosystem (Maven, npm, PyPI, etc.)
    
    Returns:
        List of vulnerability dictionaries with standardized format
    """
    
    vulnerabilities = []
    
    try:
        # Build search query - search by keyword in CVE descriptions
        # This is a limitation of NVD - it doesn't have direct package name lookups
        search_keyword = package_name.lower()
        
        params = {
            "keywordSearch": search_keyword,
            "resultsPerPage": 20  # Limit to avoid too many results
        }
        
        # Add rate limiting to respect NVD API limits (5 req/30s)
        time.sleep(6)  # Wait 6 seconds between requests
        
        response = requests.get(NVD_API_BASE, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Parse CVE items
            cve_items = data.get("vulnerabilities", [])
            
            for item in cve_items:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "UNKNOWN")
                
                # Extract CVSS score (prefer v3.1, fallback to v3.0, then v2.0)
                cvss_score = None
                cvss_vector = None
                
                metrics = cve_data.get("metrics", {})
                
                # Try CVSS v3.1
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                # Try CVSS v3.0
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                # Fallback to CVSS v2
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                
                # Extract description
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Extract published and modified dates
                published = cve_data.get("published", "")
                modified = cve_data.get("lastModified", "")
                
                # Check if this CVE is actually relevant to the package version
                # This is a heuristic - NVD doesn't provide exact package version matching
                # We rely on the fact that the keyword search should be reasonably accurate
                
                vuln = {
                    "id": cve_id,
                    "source": "NVD",
                    "package": package_name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "cvss": cvss_score,
                    "cvss_vector": cvss_vector,
                    "description": description,
                    "published": published,
                    "modified": modified,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "raw_data": cve_data  # Keep full data for reference
                }
                
                vulnerabilities.append(vuln)
        
        elif response.status_code == 403:
            print(f"⚠️  NVD API rate limit exceeded - skipping NVD results for {package_name}")
        else:
            print(f"⚠️  NVD API returned status {response.status_code} for {package_name}")
    
    except requests.exceptions.Timeout:
        print(f"⚠️  NVD API timeout for {package_name} - skipping")
    except Exception as e:
        print(f"⚠️  NVD query failed for {package_name}: {str(e)}")
    
    return vulnerabilities


def get_cve_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed information for a specific CVE from NVD.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
    
    Returns:
        Dictionary with CVE details or None if not found
    """
    
    try:
        # Rate limiting
        time.sleep(6)
        
        params = {"cveId": cve_id}
        response = requests.get(NVD_API_BASE, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                cve_data = vulnerabilities[0].get("cve", {})
                
                # Extract CVSS
                cvss_score = None
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore")
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore")
                
                return {
                    "id": cve_id,
                    "source": "NVD",
                    "cvss": cvss_score,
                    "raw_data": cve_data
                }
    
    except Exception as e:
        print(f"⚠️  Failed to get NVD details for {cve_id}: {str(e)}")
    
    return None
