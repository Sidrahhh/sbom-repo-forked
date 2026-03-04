import requests

OSV_API_URL = "https://api.osv.dev/v1/query"


def query_osv(package_name, version, ecosystem=None):
    payload = {
        "package": {
            "name": package_name
        },
        "version": version
    }

    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem

    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[ERROR] OSV query failed for {package_name}: {e}")
        return []

    vulnerabilities = []

    for vuln in data.get("vulns", []):
        cvss_score = None

        # Try to extract CVSS from severity field
        if "severity" in vuln:
            for sev in vuln["severity"]:
                try:
                    cvss_score = float(sev.get("score"))
                    break
                except:
                    continue

        # Try to extract from database_specific field (common in OSV)
        if cvss_score is None and "database_specific" in vuln:
            try:
                db_spec = vuln["database_specific"]
                if "severity" in db_spec:
                    # GitHub Advisory severity mappings
                    severity_map = {
                        "CRITICAL": 9.5,
                        "HIGH": 7.5,
                        "MODERATE": 5.0,
                        "MEDIUM": 5.0,
                        "LOW": 2.5
                    }
                    cvss_score = severity_map.get(db_spec["severity"].upper(), None)
            except:
                pass

        # Mark as UNKNOWN (0.0) if no score available instead of assuming HIGH
        # This prevents false positives
        if cvss_score is None:
            cvss_score = 0.0  # UNKNOWN - will be marked as needing manual review

        vulnerabilities.append({
            "id": vuln.get("id"),
            "source": "OSV",
            "summary": vuln.get("summary"),
            "cvss": cvss_score,
            "has_cvss": cvss_score > 0.0  # Flag for manual review if needed
        })

    return vulnerabilities