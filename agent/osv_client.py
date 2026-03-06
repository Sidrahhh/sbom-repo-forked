import requests
from agent.config_loader import get_config


def _parse_cvss_score(score_string):
    """Parse numeric CVSS base score from a vector string (e.g. CVSS:3.1/AV:N/...).
    Falls back to None if parsing fails."""
    if not score_string or not isinstance(score_string, str):
        return None
    # Already a plain number
    try:
        return float(score_string)
    except (ValueError, TypeError):
        pass
    # CVSS vector string — use the cvss library to compute the base score
    try:
        from cvss import CVSS3
        c = CVSS3(score_string)
        return float(c.base_score)
    except Exception:
        pass
    return None


def query_osv(package_name, version, ecosystem=None):
    """Query OSV API for vulnerabilities"""
    cfg = get_config()
    osv_api_url = cfg.get_api_endpoint('osv')

    payload = {
        "package": {
            "name": package_name
        },
        "version": version
    }

    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem

    try:
        response = requests.post(osv_api_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[ERROR] OSV query failed for {package_name}: {e}")
        return []

    vulnerabilities = []

    # Get CVSS numeric values from config
    cvss_values = cfg.get_cvss_numeric_values()

    for vuln in data.get("vulns", []):
        cvss_score = None

        # Try to extract CVSS from severity field (score may be a vector string)
        if "severity" in vuln:
            for sev in vuln["severity"]:
                parsed = _parse_cvss_score(sev.get("score"))
                if parsed is not None:
                    cvss_score = parsed
                    break

        # Try to extract from database_specific field (common in OSV)
        if cvss_score is None and "database_specific" in vuln:
            try:
                db_spec = vuln["database_specific"]
                if "severity" in db_spec:
                    # Use severity mappings from config
                    severity_text = db_spec["severity"].upper()
                    cvss_score = cvss_values.get(severity_text, None)
            except:
                pass

        # Mark as UNKNOWN if no score available instead of assuming HIGH
        # This prevents false positives
        if cvss_score is None:
            cvss_score = cvss_values.get('UNKNOWN', 0.0)

        vulnerabilities.append({
            "id": vuln.get("id"),
            "source": "OSV",
            "summary": vuln.get("summary"),
            "cvss": cvss_score,
            "has_cvss": cvss_score > 0.0,  # Flag for manual review if needed
            "raw_data": vuln  # Include full OSV data for remediation extraction
        })

    return vulnerabilities