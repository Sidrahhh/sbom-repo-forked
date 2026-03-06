"""
PRISM Classification Metrics — Full Pipeline Run (live OSV)
Runs the complete pipeline on each labeled SBOM and computes:
  TP, TN, FP, FN, Accuracy, Precision, Recall, Specificity, F1, FPR, FNR
"""
import sys, os, time
sys.path.insert(0, '.')
from agent.sbom_parser import load_sbom, extract_components
from agent.osv_client import query_osv
from agent.risk_engine import compute_risk
from agent.policy_engine import evaluate_policy, load_rules
from agent.config_loader import get_config
from agent.remediation_advisor import generate_remediation_summary

rules = load_rules()

# -----------------------------------------------------------------------
# Labeled dataset — ground truth (50 SBOMs)
# FAIL = pipeline should return FAIL (blocked OR has real vulnerabilities)
# PASS = pipeline should return PASS (no vulns, no blocked packages)
# -----------------------------------------------------------------------
T = "tests/test_data"
labeled = [
    # --- Original samples (1-6) ---
    ("samples/sample_sbom.json",                   "FAIL", "log4j-core 2.14.1 (Log4Shell)"),
    ("samples/fail_sbom.json",                     "FAIL", "lodash 4.17.20 vulns"),
    ("samples/sbom_dev_only.json",                 "PASS", "lodash dev-only scope"),
    ("samples/sbom_with_scope.json",               "FAIL", "scoped vuln present"),
    (f"{T}/sbom_merge_allowed.json",               "FAIL", "lodash 4.17.20 (vuln, not blocked)"),
    (f"{T}/sbom_merge_blocked.json",               "FAIL", "blocked: openssl"),
    # --- First batch (7-12) ---
    (f"{T}/sbom_clean_jquery.json",                "PASS", "jquery 3.7.1 clean"),
    (f"{T}/sbom_vuln_axios.json",                  "FAIL", "axios 0.21.0 SSRF"),
    (f"{T}/sbom_blocked_openssl.json",             "FAIL", "openssl blocked"),
    (f"{T}/sbom_mixed_safe_vuln.json",             "FAIL", "lodash 4.17.20 in mix"),
    (f"{T}/sbom_clean_safe_versions.json",         "PASS", "lodash 4.17.23 + express safe"),
    (f"{T}/sbom_multi_vuln.json",                  "FAIL", "lodash + axios both vuln"),
    # --- Single vulnerable (13-31) ---
    (f"{T}/sbom_vuln_minimist.json",               "FAIL", "minimist 1.2.0 prototype pollution"),
    (f"{T}/sbom_vuln_nodefetch.json",              "FAIL", "node-fetch 2.6.0 ReDoS"),
    (f"{T}/sbom_vuln_handlebars.json",             "FAIL", "handlebars 4.5.2 prototype pollution"),
    (f"{T}/sbom_vuln_serialize_js.json",           "FAIL", "serialize-javascript 1.7.0 XSS"),
    (f"{T}/sbom_vuln_jquery_old.json",             "FAIL", "jquery 1.9.0 XSS"),
    (f"{T}/sbom_vuln_marked.json",                 "FAIL", "marked 0.3.6 ReDoS"),
    (f"{T}/sbom_vuln_tar.json",                    "FAIL", "tar 4.4.8 path traversal"),
    (f"{T}/sbom_vuln_ws.json",                     "FAIL", "ws 6.2.1 ReDoS"),
    (f"{T}/sbom_vuln_underscore.json",             "FAIL", "underscore 1.12.0 prototype pollution"),
    (f"{T}/sbom_vuln_dotprop.json",                "FAIL", "dot-prop 4.2.0 prototype pollution"),
    (f"{T}/sbom_vuln_pathparse.json",              "FAIL", "path-parse 1.0.6 ReDoS"),
    (f"{T}/sbom_vuln_immer.json",                  "FAIL", "immer 8.0.0 prototype pollution"),
    (f"{T}/sbom_vuln_y18n.json",                   "FAIL", "y18n 4.0.0 prototype pollution"),
    (f"{T}/sbom_vuln_ini.json",                    "FAIL", "ini 1.3.5 prototype pollution"),
    (f"{T}/sbom_vuln_lodash_old.json",             "FAIL", "lodash 4.17.4 (older, vuln)"),
    (f"{T}/sbom_vuln_ansi_regex.json",             "FAIL", "ansi-regex 4.1.0 ReDoS"),
    (f"{T}/sbom_vuln_glob_parent.json",            "FAIL", "glob-parent 3.1.0 ReDoS"),
    (f"{T}/sbom_vuln_set_value.json",              "FAIL", "set-value 2.0.0 prototype pollution"),
    (f"{T}/sbom_vuln_object_path.json",            "FAIL", "object-path 0.11.4 prototype pollution"),
    # --- Single safe (32-39) ---
    (f"{T}/sbom_safe_chalk.json",                  "PASS", "chalk 5.3.0 safe"),
    (f"{T}/sbom_safe_uuid.json",                   "PASS", "uuid 9.0.0 safe"),
    (f"{T}/sbom_safe_typescript.json",             "PASS", "typescript 5.4.0 safe"),
    (f"{T}/sbom_safe_axios_new.json",              "FAIL", "axios 1.6.0 (has CVEs)"),
    (f"{T}/sbom_safe_commander.json",              "PASS", "commander 11.0.0 safe"),
    (f"{T}/sbom_safe_dotenv.json",                 "PASS", "dotenv 16.3.1 safe"),
    (f"{T}/sbom_safe_react.json",                  "PASS", "react 18.2.0 safe"),
    (f"{T}/sbom_safe_mocha.json",                  "PASS", "mocha 10.2.0 safe"),
    # --- Additional blocked (40) ---
    (f"{T}/sbom_blocked_openssl_v2.json",          "FAIL", "openssl 2.0.0 blocked by policy"),
    # --- Multi-component (41-50) ---
    (f"{T}/sbom_multi_all_safe.json",              "PASS", "chalk + uuid + commander all safe"),
    (f"{T}/sbom_multi_vuln_mixed2.json",           "FAIL", "lodash 4.17.20 + node-fetch vuln"),
    (f"{T}/sbom_multi_safe_one_vuln.json",         "FAIL", "chalk safe + handlebars vuln"),
    (f"{T}/sbom_multi_blocked_safe.json",          "FAIL", "openssl blocked + chalk safe"),
    (f"{T}/sbom_multi_three_safe.json",            "PASS", "typescript + uuid + dotenv safe"),
    (f"{T}/sbom_multi_all_vuln.json",              "FAIL", "minimist + y18n + ini all vuln"),
    (f"{T}/sbom_multi_safe_large.json",            "FAIL", "express + axios(vuln) + chalk + uuid"),
    (f"{T}/sbom_multi_blocked_clean.json",         "FAIL", "lodash 4.17.23 safe + openssl blocked"),
    (f"{T}/sbom_multi_critical.json",              "FAIL", "lodash + handlebars + axios all vuln"),
    (f"{T}/sbom_empty.json",                       "PASS", "empty SBOM — no components"),
    # --- Cross-ecosystem & severity edge cases (51-56) ---
    (f"{T}/sbom_maven_log4j.json",                 "FAIL", "Maven: log4j-core 2.14.1 (Log4Shell)"),
    (f"{T}/sbom_maven_safe.json",                  "PASS", "Maven: guava 32.1.3 safe"),
    (f"{T}/sbom_pypi_requests_vuln.json",           "FAIL", "PyPI: requests 2.25.0 vuln"),
    (f"{T}/sbom_pypi_safe.json",                   "PASS", "PyPI: boto3 1.34.0 safe"),
    (f"{T}/sbom_low_severity_only.json",           "PASS", "LOW severity only — should PASS"),
    (f"{T}/sbom_critical_lodash.json",             "FAIL", "CRITICAL: lodash 4.17.15"),
]

def run_pipeline(sbom_path):
    sbom_data = load_sbom(sbom_path)
    components = extract_components(sbom_data)
    findings = []
    for comp in components:
        vulns = query_osv(comp["name"], comp["version"], comp.get("ecosystem"))
        findings.append({"component": comp, "vulnerabilities": vulns})
    risk_summary = compute_risk(findings)
    remediations = generate_remediation_summary(findings)
    decision, reason = evaluate_policy(risk_summary, findings, rules)
    return decision, reason, findings

print("=" * 70)
print("PRISM CLASSIFICATION METRICS — FULL PIPELINE (live OSV API)")
print("=" * 70)
print(f"\nRunning on {len(labeled)} labeled SBOMs...\n")
print(f"  {'Label':<43} {'GT':<6} {'Got':<6} {'Result'}")
print("  " + "-" * 65)

TP = TN = FP = FN = 0
results = []

for sbom_path, ground_truth, description in labeled:
    if not os.path.exists(sbom_path):
        print(f"  {description:<43} SKIP (file not found: {sbom_path})")
        continue

    t0 = time.perf_counter()
    decision, reason, findings = run_pipeline(sbom_path)
    elapsed = (time.perf_counter() - t0) * 1000

    vuln_count = sum(len(f["vulnerabilities"]) for f in findings)

    if ground_truth == "FAIL" and decision == "FAIL":
        TP += 1; outcome = "TP ✓"
    elif ground_truth == "PASS" and decision == "PASS":
        TN += 1; outcome = "TN ✓"
    elif ground_truth == "PASS" and decision == "FAIL":
        FP += 1; outcome = "FP ✗"
    else:
        FN += 1; outcome = "FN ✗"

    results.append((description, ground_truth, decision, outcome, vuln_count, elapsed, reason))
    print(f"  {description:<43} {ground_truth:<6} {decision:<6} {outcome}  ({vuln_count} vulns, {elapsed:.0f}ms)")

total = TP + TN + FP + FN

print(f"\n{'='*70}")
print("CONFUSION MATRIX")
print(f"  TP (correctly flagged FAIL) = {TP}")
print(f"  TN (correctly flagged PASS) = {TN}")
print(f"  FP (wrongly flagged FAIL)   = {FP}")
print(f"  FN (missed real FAIL)       = {FN}")
print(f"  Total                       = {total}")

if total > 0:
    accuracy    = (TP + TN) / total * 100
    precision   = (TP / (TP + FP)         * 100) if (TP + FP)         > 0 else float('nan')
    recall      = (TP / (TP + FN)         * 100) if (TP + FN)         > 0 else float('nan')
    specificity = (TN / (TN + FP)         * 100) if (TN + FP)         > 0 else float('nan')
    f1          = (2*TP / (2*TP + FP + FN)* 100) if (2*TP + FP + FN)  > 0 else float('nan')
    fpr         = (FP / (FP + TN)         * 100) if (FP + TN)         > 0 else float('nan')
    fnr         = (FN / (FN + TP)         * 100) if (FN + TP)         > 0 else float('nan')

    print(f"\n{'='*70}")
    print("CLASSIFICATION METRICS")
    print(f"  Accuracy    (TP+TN)/Total   = {accuracy:.1f}%")
    print(f"  Precision   TP/(TP+FP)      = {precision:.1f}%")
    print(f"  Recall/Sens TP/(TP+FN)      = {recall:.1f}%")
    print(f"  Specificity TN/(TN+FP)      = {specificity:.1f}%")
    print(f"  F1 Score    2TP/(2TP+FP+FN) = {f1:.1f}%")
    print(f"  FPR         FP/(FP+TN)      = {fpr:.1f}%")
    print(f"  FNR         FN/(FN+TP)      = {fnr:.1f}%")

print(f"\n{'='*70}")
print("FALSE POSITIVES (if any):")
for desc, gt, dec, outcome, v, e, reason in results:
    if "FP" in outcome:
        print(f"  {desc}: GT={gt} Got={dec} Reason={reason}")

print("\nFALSE NEGATIVES (if any):")
for desc, gt, dec, outcome, v, e, reason in results:
    if "FN" in outcome:
        print(f"  {desc}: GT={gt} Got={dec} Reason={reason}")

print("\nDone.\n")
