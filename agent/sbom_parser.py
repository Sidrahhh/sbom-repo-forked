import json


def load_sbom(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_purl(purl):
    """
    Parse package URL and extract ecosystem + normalized name
    """
    # Example: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
    try:
        purl = purl.replace("pkg:", "")
        parts = purl.split("/")

        ecosystem_raw = parts[0]
        remainder = "/".join(parts[1:])

        name_version = remainder.split("@")
        name_part = name_version[0]

        if ecosystem_raw == "maven":
            # namespace/name → namespace:name
            namespace, name = name_part.split("/")
            normalized_name = f"{namespace}:{name}"
            ecosystem = "Maven"

        elif ecosystem_raw == "pypi":
            normalized_name = name_part
            ecosystem = "PyPI"

        elif ecosystem_raw == "npm":
            normalized_name = name_part
            ecosystem = "npm"

        elif ecosystem_raw == "golang":
            normalized_name = name_part
            ecosystem = "Go"

        elif ecosystem_raw == "nuget":
            normalized_name = name_part
            ecosystem = "NuGet"

        elif ecosystem_raw == "rubygems":
            normalized_name = name_part
            ecosystem = "RubyGems"

        else:
            normalized_name = name_part
            ecosystem = None

        return ecosystem, normalized_name

    except Exception:
        return None, None


def extract_components(sbom_json):
    components = []
    seen = set()

    for comp in sbom_json.get("components", []):
        name = comp.get("name")
        version = comp.get("version")
        purl = comp.get("purl")

        ecosystem = None
        normalized_name = name

        if purl:
            ecosystem, normalized_name = parse_purl(purl)

        if normalized_name and version:
            dedupe_key = (normalized_name, version, ecosystem)
            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)
            components.append({
                "name": normalized_name,
                "version": version,
                "ecosystem": ecosystem
            })

    return components