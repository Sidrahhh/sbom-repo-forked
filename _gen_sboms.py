"""Generate 38 additional labeled SBOM files to reach 50 total test cases."""
import json, os

base = "tests/test_data"
os.makedirs(base, exist_ok=True)

def sbom(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": components}

def comp(name, version, ecosystem="npm", scope=None, dev=False):
    c = {"type": "library", "purl": f"pkg:{ecosystem}/{name}@{version}", "name": name, "version": version}
    if scope:
        c["scope"] = scope
    if dev:
        c["properties"] = [{"name": "cdx:npm:package:development", "value": "true"}]
    return c

files = {
    # ---- Single vulnerable ----
    "sbom_vuln_minimist.json":       sbom([comp("minimist",            "1.2.0")]),
    "sbom_vuln_nodefetch.json":      sbom([comp("node-fetch",          "2.6.0")]),
    "sbom_vuln_handlebars.json":     sbom([comp("handlebars",          "4.5.2")]),
    "sbom_vuln_serialize_js.json":   sbom([comp("serialize-javascript","1.7.0")]),
    "sbom_vuln_jquery_old.json":     sbom([comp("jquery",              "1.9.0")]),
    "sbom_vuln_marked.json":         sbom([comp("marked",              "0.3.6")]),
    "sbom_vuln_tar.json":            sbom([comp("tar",                 "4.4.8")]),
    "sbom_vuln_ws.json":             sbom([comp("ws",                  "6.2.1")]),
    "sbom_vuln_underscore.json":     sbom([comp("underscore",          "1.12.0")]),
    "sbom_vuln_dotprop.json":        sbom([comp("dot-prop",            "4.2.0")]),
    "sbom_vuln_pathparse.json":      sbom([comp("path-parse",          "1.0.6")]),
    "sbom_vuln_immer.json":          sbom([comp("immer",               "8.0.0")]),
    "sbom_vuln_y18n.json":           sbom([comp("y18n",                "4.0.0")]),
    "sbom_vuln_ini.json":            sbom([comp("ini",                 "1.3.5")]),
    "sbom_vuln_lodash_old.json":     sbom([comp("lodash",              "4.17.4")]),
    "sbom_vuln_ansi_regex.json":     sbom([comp("ansi-regex",          "4.1.0")]),
    "sbom_vuln_glob_parent.json":    sbom([comp("glob-parent",         "3.1.0")]),
    "sbom_vuln_set_value.json":      sbom([comp("set-value",           "2.0.0")]),
    "sbom_vuln_object_path.json":    sbom([comp("object-path",         "0.11.4")]),
    # ---- Single safe ----
    "sbom_safe_chalk.json":          sbom([comp("chalk",      "5.3.0")]),
    "sbom_safe_uuid.json":           sbom([comp("uuid",       "9.0.0")]),
    "sbom_safe_typescript.json":     sbom([comp("typescript", "5.4.0")]),
    "sbom_safe_axios_new.json":      sbom([comp("axios",      "1.6.0")]),
    "sbom_safe_commander.json":      sbom([comp("commander",  "11.0.0")]),
    "sbom_safe_dotenv.json":         sbom([comp("dotenv",     "16.3.1")]),
    "sbom_safe_react.json":          sbom([comp("react",      "18.2.0")]),
    "sbom_safe_mocha.json":          sbom([comp("mocha",      "10.2.0")]),
    # ---- Additional blocked ----
    "sbom_blocked_openssl_v2.json":  sbom([comp("openssl",    "2.0.0")]),
    # ---- Multi-component scenarios ----
    "sbom_multi_all_safe.json":      sbom([comp("chalk","5.3.0"), comp("uuid","9.0.0"), comp("commander","11.0.0")]),
    "sbom_multi_vuln_mixed2.json":   sbom([comp("lodash","4.17.20"), comp("node-fetch","2.6.0")]),
    "sbom_multi_safe_one_vuln.json": sbom([comp("chalk","5.3.0"), comp("handlebars","4.5.2")]),
    "sbom_multi_blocked_safe.json":  sbom([comp("openssl","1.0.0"), comp("chalk","5.3.0")]),
    "sbom_multi_three_safe.json":    sbom([comp("typescript","5.4.0"), comp("uuid","9.0.0"), comp("dotenv","16.3.1")]),
    "sbom_multi_all_vuln.json":      sbom([comp("minimist","1.2.0"), comp("y18n","4.0.0"), comp("ini","1.3.5")]),
    "sbom_multi_safe_large.json":    sbom([comp("express","4.21.2"), comp("axios","1.6.0"), comp("chalk","5.3.0"), comp("uuid","9.0.0")]),
    "sbom_multi_blocked_clean.json": sbom([comp("lodash","4.17.23"), comp("openssl","1.0.0")]),
    "sbom_multi_critical.json":      sbom([comp("lodash","4.17.20"), comp("handlebars","4.5.2"), comp("axios","0.21.0")]),
    "sbom_empty.json":               sbom([]),
}

for fname, data in files.items():
    path = os.path.join(base, fname)
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  Created: {path}")
    else:
        print(f"  Exists:  {path}")

print(f"\nDone. {len(files)} files processed.")
