# PRISM

**Pull-Request Integrated Security Mechanism**

> A CI/CD-native security framework that automates Software Bill of Materials (SBOM) generation, real-time vulnerability scanning, AI-powered remediation guidance, and policy-as-code enforcement — triggered on every pull request.

---

## Overview

Modern software supply chains face increasing threats from vulnerable dependencies and malicious packages. Traditional security scans often occur post-merge, leaving critical vulnerabilities undetected until production. **PRISM** addresses this gap by integrating a full security pipeline directly into the pull request workflow.

This repository implements **Objectives 1 & 2** of the PRISM framework:

- **Objective 1** — Automated SBOM generation on every PR
- **Objective 2** — Autonomous vulnerability detection, risk scoring, AI-powered remediation, and policy gate enforcement

---

## Project Objectives

| # | Objective | Status |
|---|-----------|--------|
| 01 | Automate SBOM generation for every PR using GitHub Actions | ✅ Implemented |
| 02 | Autonomous vulnerability detection, risk scoring, AI remediation & policy gates | ✅ Implemented |
| 03 | Deep reachability analysis and signed compliance artifacts | 🔄 Phase 3 |

---

## Full Pipeline: How It Works

When a developer opens or updates a pull request, PRISM executes a 6-stage security pipeline automatically:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   PR Opens  │───▶│ SBOM        │───▶│ OSV Vuln    │───▶│ Risk        │───▶│ Policy      │───▶│ PR Comment  │
│  / Updates  │    │ Generated   │    │ Scanning    │    │ Scoring     │    │ Gate        │    │ + Artifacts │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                              │                                      │
                                              ▼                                      ▼
                                     ┌─────────────┐                       ┌─────────────┐
                                     │ AI-Powered  │                       │ PASS / WARN │
                                     │ Remediation │                       │ / FAIL      │
                                     └─────────────┘                       └─────────────┘
```

### Stage 1 — SBOM Generation (Objective 1)

- Triggered automatically on PR `opened`, `synchronize`, `reopened` events
- Uses **Anchore Syft** (`sbom-action`) to generate a **CycloneDX JSON** SBOM
- Captures all direct **and transitive** dependencies resolved after `npm install`
- Uploads the SBOM as a PR-scoped build artifact (`sbom-pr-<number>.json`)

### Stage 2 — Vulnerability Scanning via OSV (Objective 2)

- Each component in the SBOM is queried against the **OSV (Open Source Vulnerabilities)** API
- Returns CVE/GHSA advisory IDs, CVSS vector strings, severity, and full advisory details
- CVSS scores are computed directly from the vector string (e.g. `CVSS:3.1/AV:N/...`) using the `cvss` library for accuracy — not estimated from severity labels

### Stage 3 — Risk Scoring

A composite risk score (0–10 scale) is calculated per scan:

```
Risk Score = (weight_vuln × vuln_count_factor) + (weight_cvss × max_cvss)
```

Weights and thresholds are fully configurable in [`config/prism_config.yaml`](config/prism_config.yaml).

| CVSS Range | Severity |
|------------|----------|
| ≥ 9.0      | CRITICAL |
| ≥ 7.0      | HIGH     |
| ≥ 4.0      | MEDIUM   |
| ≥ 0.1      | LOW      |
| 0.0        | UNKNOWN  |

### Stage 4 — AI-Powered Remediation (Objective 2)

When an `OPENAI_API_KEY` is present, PRISM uses **GPT-4** to generate context-aware remediation advice that goes beyond a simple "upgrade to X.Y.Z":

- Reads the actual codebase for usage context
- Predicts breaking changes between versions
- Generates natural-language migration guides
- Recommends testing strategies specific to the project
- Explains *why* a vulnerability matters in this codebase

Falls back gracefully to static rule-based remediation when no API key is configured.

### Stage 5 — Policy Gate Enforcement

Decisions are driven by [`policies/default_policy.yaml`](policies/default_policy.yaml) and [`rules/blocked_packages.yaml`](rules/blocked_packages.yaml):

| Rule Type | Description |
|-----------|-------------|
| **Blocked packages** | Any package listed in `blocked_packages.yaml` causes an immediate FAIL, regardless of CVSS score |
| **Severity gate** | CRITICAL or HIGH findings → `FAIL`; MEDIUM → `WARN`; LOW/UNKNOWN → `PASS` |
| **Advanced conditional rules** | `rules:` block in YAML supports `deny`/`warn`/`allow` with `severity ==`, `reachable ==`, and `severity in [...]` conditions |

Blocked packages appear in the report with an ⛔ **BLOCKED BY POLICY** indicator.

### Stage 6 — PR Comment & Artifacts

- Structured Markdown report posted as a PR comment with decision, risk score, all CVEs, and remediation steps
- Full `report.json` and `pr_comment.md` uploaded as workflow artifacts

---

## Objective 1: Automated SBOM Generation

### SBOM Format

The generated SBOM follows the **CycloneDX v1.4+** specification:

- Component names, versions, and package URLs (purl)
- Full dependency tree including transitive dependencies
- License information
- Cryptographic hashes (SHA-256, SHA-512)

Example component entry:
```json
{
  "type": "library",
  "bom-ref": "pkg:npm/lodash@4.17.23",
  "name": "lodash",
  "version": "4.17.23",
  "purl": "pkg:npm/lodash@4.17.23",
  "licenses": [{ "license": { "id": "MIT" } }]
}
```

---

## Objective 2: Vulnerability Detection & AI Remediation

### Sample PR Comment Output

```
## 🔐 PRISM Security Scan Results

**Decision:** ✗ FAIL
**Overall Severity:** CRITICAL
**Risk Score:** 8.1 / 10
**Max CVSS:** 9.8
**Total Vulnerabilities:** 2

### Vulnerable Components

#### openssl@1.0.0 ⛔ BLOCKED BY POLICY

- GHSA-75w2-qv55-x7fv (CVSS: 9.8, Severity: CRITICAL) [Source: OSV]

#### mout@0.11.1

- GHSA-pc58-wgmc-hfjr (CVSS: 7.5, Severity: HIGH) [Source: OSV]

### 🛡️ Policy Decision

Blocked package detected: openssl
```

### Supported Ecosystems

| Ecosystem | Detection Method |
|-----------|-----------------|
| npm / Node.js | `package.json`, purl `pkg:npm/` |
| PyPI / Python | `requirements.txt`, purl `pkg:pypi/` |
| Maven / Java | `pom.xml`, purl `pkg:maven/` |
| Go | purl `pkg:golang/` |
| NuGet / .NET | purl `pkg:nuget/` |
| RubyGems | purl `pkg:gem/` |

---

## Repository Structure

```
sbom-repo/
├── .github/
│   └── workflows/
│       └── sbom.yml               # GitHub Actions workflow
├── agent/
│   ├── main.py                    # Pipeline entrypoint
│   ├── sbom_parser.py             # CycloneDX SBOM loader & component extractor
│   ├── osv_client.py              # OSV API client with CVSS vector parsing
│   ├── risk_engine.py             # Composite risk score calculator
│   ├── policy_engine.py           # Policy gate evaluator (blocked pkgs + rules)
│   ├── ai_remediation_advisor.py  # GPT-4 context-aware remediation
│   ├── remediation_advisor.py     # Fallback static remediation
│   ├── reporter.py                # Markdown + JSON report generator
│   ├── config_loader.py           # Config reader with safe defaults
│   └── utils.py                   # CVSS → severity helpers
├── config/
│   └── prism_config.yaml          # All tunable parameters (weights, thresholds, model)
├── policies/
│   └── default_policy.yaml        # Severity-based policy gates (FAIL/WARN/PASS)
├── rules/
│   └── blocked_packages.yaml      # Hard-block list (any version unless pinned)
├── samples/
│   ├── sample_sbom.json           # Clean SBOM (PASS scenario)
│   ├── fail_sbom.json             # Vulnerable SBOM (FAIL scenario)
│   ├── sbom_dev_only.json         # Dev-only scoped SBOM
│   └── sbom_with_scope.json       # Scoped dependency SBOM
├── tests/                         # Pytest test suite
├── package.json                   # Demo Node.js project
└── requirements.txt               # Python dependencies
```

---

## Configuration

### `config/prism_config.yaml`

All scoring parameters, AI settings, and API endpoints are centralised here:

```yaml
risk_scoring:
  formula:
    weights:
      vulnerability_count: 0.4
      cvss_score: 0.6
  cvss_severity:
    critical:
      threshold: 9.0
      numeric_value: 9.5   # fallback if no vector string available

openai:
  model: gpt-4
  temperature: 0.3
  max_tokens: 2000
```

### `rules/blocked_packages.yaml`

List package names to hard-block regardless of version or CVE status:

```yaml
blocked_packages:
  - openssl        # blocks any version
  - log4j-core     # example: block by name
```

To block only a specific version, use the `policies/default_policy.yaml` advanced rules format instead.

### `policies/default_policy.yaml`

Controls the PR decision thresholds:

```yaml
policy_gates:
  fail_on: [CRITICAL, HIGH]
  warn_on: [MEDIUM]
  allow:   [LOW, UNKNOWN]
```

Advanced conditional rules are also supported:

```yaml
rules:
  - type: deny
    when: severity == "CRITICAL" and reachable == true
    msg: "Critical reachable vulnerability — block PR"
  - type: warn
    when: severity in ["MEDIUM"]
    msg: "Medium severity — review before merging"
```

---

## Usage

### Prerequisites

- GitHub repository with Actions enabled
- `OPENAI_API_KEY` secret set in repo settings (optional — AI remediation degrades gracefully without it)

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run against a sample SBOM
python -m agent.main samples/fail_sbom.json --output output/

# Run without AI (faster, no API key needed)
python -m agent.main samples/fail_sbom.json --output output/ --no-ai

# Run with a custom rules file
python -m agent.main samples/fail_sbom.json --rules rules/blocked_packages.yaml
```

### Triggering the CI Workflow

1. Create a new branch and make changes to `package.json`
2. Open a Pull Request against `main`
3. The workflow triggers automatically
4. Results appear as a PR comment within ~2 minutes
5. Download full artifacts from **Actions → Artifacts**

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| CI/CD Platform | GitHub Actions |
| SBOM Generator | Anchore Syft (`sbom-action`) |
| SBOM Format | CycloneDX JSON |
| Vulnerability Database | OSV (Open Source Vulnerabilities) |
| CVSS Parsing | `cvss` Python library |
| AI Remediation | OpenAI GPT-4 |
| Policy Engine | YAML-based (Python) |
| Runtime | Ubuntu Latest / Python 3.12 |

---

## References

- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [OSV — Open Source Vulnerability Database](https://osv.dev/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/page/software-bill-materials)
- [Anchore Syft](https://github.com/anchore/syft)
- [OWASP Dependency-Track](https://dependencytrack.org/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)

---

## Team

**Department of Computer Science & Engineering (Cyber Security)**  
Ramaiah Institute of Technology

| Name | USN |
|------|-----|
| Aadarsh G K | 1MS22CY001 |
| Divith V | 1MS22CY023 |
| Sidrah Saif | 1MS22CY067 |

**Guide:** Dr. Siddesh G.M., Professor and Head, Dept. of CSE (Cyber Security)

---

## License

This project is part of an academic major project for demonstration purposes.

---

<p align="center">
  <sub>Built with 🔒 for secure software supply chains</sub>
</p>

