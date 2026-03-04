"""
CISA KEV (Known Exploited Vulnerabilities) Client

CISA maintains a catalog of known exploited vulnerabilities that carry significant risk.
Catalog URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

This client checks if detected CVEs are in the CISA KEV catalog, indicating
active exploitation in the wild and requiring urgent remediation.
"""

import requests
from typing import List, Dict, Any, Set, Optional
from datetime import datetime


CISA_KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cache the KEV catalog to avoid downloading it multiple times
_kev_catalog_cache = None
_kev_cache_timestamp = None


def load_kev_catalog(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Load the CISA KEV catalog (cached for performance).
    
    Args:
        force_refresh: Force download even if cached
    
    Returns:
        Dictionary containing the full KEV catalog
    """
    global _kev_catalog_cache, _kev_cache_timestamp
    
    # Use cache if available and not forcing refresh
    if not force_refresh and _kev_catalog_cache is not None:
        return _kev_catalog_cache
    
    try:
        response = requests.get(CISA_KEV_CATALOG_URL, timeout=15)
        
        if response.status_code == 200:
            _kev_catalog_cache = response.json()
            _kev_cache_timestamp = datetime.now()
            return _kev_catalog_cache
        else:
            print(f"⚠️  Failed to load CISA KEV catalog: HTTP {response.status_code}")
            return {}
    
    except requests.exceptions.Timeout:
        print(f"⚠️  CISA KEV catalog download timeout")
        return {}
    except Exception as e:
        print(f"⚠️  Failed to load CISA KEV catalog: {str(e)}")
        return {}


def get_kev_cve_set() -> Set[str]:
    """
    Get a set of all CVE IDs in the CISA KEV catalog.
    
    Returns:
        Set of CVE IDs (e.g., {"CVE-2021-44228", "CVE-2021-45046", ...})
    """
    catalog = load_kev_catalog()
    vulnerabilities = catalog.get("vulnerabilities", [])
    
    return {vuln.get("cveID") for vuln in vulnerabilities if vuln.get("cveID")}


def check_kev_status(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Check if a CVE is in the CISA KEV catalog.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
    
    Returns:
        Dictionary with KEV details if found, None otherwise
        {
            "cve_id": str,
            "in_kev": bool,
            "vendor_project": str,
            "product": str,
            "vulnerability_name": str,
            "date_added": str,
            "due_date": str,
            "required_action": str,
            "notes": str
        }
    """
    catalog = load_kev_catalog()
    vulnerabilities = catalog.get("vulnerabilities", [])
    
    for vuln in vulnerabilities:
        if vuln.get("cveID") == cve_id:
            return {
                "cve_id": cve_id,
                "in_kev": True,
                "vendor_project": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "vulnerability_name": vuln.get("vulnerabilityName", ""),
                "date_added": vuln.get("dateAdded", ""),
                "due_date": vuln.get("dueDate", ""),
                "required_action": vuln.get("requiredAction", ""),
                "notes": vuln.get("notes", ""),
                "short_description": vuln.get("shortDescription", "")
            }
    
    return {
        "cve_id": cve_id,
        "in_kev": False
    }


def enhance_vulnerabilities_with_kev(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add CISA KEV status to a list of vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
    
    Returns:
        Same list with added "kev" field containing KEV status
    """
    # Load KEV catalog once
    kev_cves = get_kev_cve_set()
    catalog = load_kev_catalog()
    kev_vulns = catalog.get("vulnerabilities", [])
    
    # Create lookup map for efficiency
    kev_map = {vuln.get("cveID"): vuln for vuln in kev_vulns}
    
    enhanced_vulns = []
    
    for vuln in vulnerabilities:
        # Check multiple ID fields
        cve_id = vuln.get("cve_id") or vuln.get("id")
        
        # Extract CVE ID from various formats
        if cve_id and cve_id.startswith("CVE-"):
            if cve_id in kev_cves:
                kev_data = kev_map.get(cve_id, {})
                vuln["kev"] = {
                    "in_kev": True,
                    "date_added": kev_data.get("dateAdded", ""),
                    "due_date": kev_data.get("dueDate", ""),
                    "required_action": kev_data.get("requiredAction", ""),
                    "notes": kev_data.get("notes", "")
                }
                # Boost severity for KEV vulnerabilities
                vuln["is_actively_exploited"] = True
            else:
                vuln["kev"] = {"in_kev": False}
                vuln["is_actively_exploited"] = False
        else:
            vuln["kev"] = {"in_kev": False}
            vuln["is_actively_exploited"] = False
        
        enhanced_vulns.append(vuln)
    
    return enhanced_vulns


def get_kev_statistics() -> Dict[str, Any]:
    """
    Get statistics about the CISA KEV catalog.
    
    Returns:
        Dictionary with catalog metadata and statistics
    """
    catalog = load_kev_catalog()
    
    if not catalog:
        return {
            "title": "Unknown",
            "catalog_version": "Unknown",
            "date_released": "Unknown",
            "total_vulnerabilities": 0
        }
    
    return {
        "title": catalog.get("title", "CISA KEV Catalog"),
        "catalog_version": catalog.get("catalogVersion", "Unknown"),
        "date_released": catalog.get("dateReleased", "Unknown"),
        "total_vulnerabilities": catalog.get("count", 0)
    }
