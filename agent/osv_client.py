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

        if "severity" in vuln:
            for sev in vuln["severity"]:
                try:
                    cvss_score = float(sev.get("score"))
                    break
                except:
                    continue

        # Fallback for demo safety
        if cvss_score is None:
            cvss_score = 7.5

        vulnerabilities.append({
            "id": vuln.get("id"),
            "summary": vuln.get("summary"),
            "cvss": cvss_score
        })

    return vulnerabilities