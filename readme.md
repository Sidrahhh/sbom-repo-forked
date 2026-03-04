# PRISM

**Pull-Request Integrated Security Mechanism**

> A CI/CD-native security framework that automates Software Bill of Materials (SBOM) generation, vulnerability analysis, and policy enforcement for every pull request.

---

## Overview

Modern software supply chains face increasing threats from vulnerable dependencies and malicious packages. Traditional security scans often occur post-merge, leaving critical vulnerabilities undetected until production. **PRISM** addresses this gap by integrating security checks directly into the pull request workflow.

This repository demonstrates **Objective 1** of the PRISM framework: automated SBOM generation triggered on every pull request.

---

## Project Objectives

| # | Objective | Status |
|---|-----------|--------|
| 01 | Automate SBOM generation for every PR using GitHub Actions | ✅ Implemented |
| 02 | Develop autonomous vulnerability detection mapping SBOM to threat intelligence | 🔄 Phase 2 |
| 03 | Integrate policy-as-code gates with remediation suggestions | 🔄 Phase 3 |

---

## Objective 1: Automated SBOM Generation

### What It Does

When a developer opens, updates, or reopens a pull request, this workflow:

1. **Triggers automatically** on PR events (`opened`, `synchronize`, `reopened`)
2. **Generates a CycloneDX SBOM** containing all direct and transitive dependencies
3. **Uploads the SBOM as a build artifact** with PR-specific naming (`sbom-pr-<number>.json`)
4. **Posts a summary comment** on the PR with component statistics and download link

### Workflow Diagram

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Developer   │────▶│  Pull Request│────▶│GitHub Action │────▶│    SBOM      │
│   Commits    │     │    Opened    │     │    Runs      │     │  Generated   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                                      │
                                                                      ▼
                                                              ┌──────────────┐
                                                              │  PR Comment  │
                                                              │  + Artifact  │
                                                              └──────────────┘
```

### SBOM Format

The generated SBOM follows the **CycloneDX v1.4+** specification, an OWASP standard that includes:

- Component names, versions, and package URLs (purl)
- Dependency tree with transitive dependencies
- License information
- Cryptographic hashes (SHA-256, SHA-512)

Example component entry:
```json
{
  "type": "library",
  "bom-ref": "pkg:npm/left-pad@1.3.0",
  "name": "left-pad",
  "version": "1.3.0",
  "purl": "pkg:npm/left-pad@1.3.0",
  "licenses": [{ "license": { "id": "MIT" } }]
}
```

---

## Repository Structure

```
sbom-repo/
├── .github/
│   └── workflows/
│       └── sbom.yml          # GitHub Actions workflow for SBOM generation
├── package.json              # Sample Node.js project with dependencies
└── README.md                 # Project documentation
```

---

## Usage

### Prerequisites

- GitHub repository with Actions enabled
- Project with a supported package manager (npm, pip, maven, etc.)

### Triggering the Workflow

1. Create a new branch and make changes
2. Open a Pull Request against `main`
3. The workflow triggers automatically
4. Check the PR comments for SBOM summary
5. Download the artifact from the Actions tab

### Viewing Artifacts

Navigate to **Actions** → Select the workflow run → **Artifacts** section → Download `sbom-pr-<number>`

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| CI/CD Platform | GitHub Actions |
| SBOM Generator | Anchore Syft |
| SBOM Format | CycloneDX JSON |
| Runtime | Ubuntu Latest |

---

## Future Phases

### Phase 2: Vulnerability Correlation (Objective 2)

- Parse generated SBOM and query OSV, NVD, and GitHub Advisory APIs
- Perform reachability analysis to filter non-exploitable vulnerabilities
- Calculate risk scores based on CVSS + exploitability

### Phase 3: Policy Gate Integration (Objective 3)

- Implement OPA/Rego or YAML-based policy rules
- Block PRs with critical reachable vulnerabilities
- Post remediation suggestions as PR comments
- Generate signed compliance artifacts

---

## References

- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/page/software-bill-materials)
- [Anchore Syft](https://github.com/anchore/syft)
- [OWASP Dependency-Track](https://dependencytrack.org/)

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
