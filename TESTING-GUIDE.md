# 🧪 TESTING GUIDE - Integration Branch

This guide shows you how to test the complete PRISM integration both locally and on GitHub.

## ✅ Local Testing (In Your VS Code Terminal)

### Quick Test - See Results Immediately

**Test 1: Safe Package (Should PASS)**
```bash
python test_local.py
```

Expected output:
```
✅ TEST PASSED - No blocking vulnerabilities
```

**Test 2: Vulnerable Package (Should FAIL)**
```bash
python test_local.py --vulnerable
```

Expected output:
```
❌ TEST FAILED - Blocking vulnerabilities detected
Max CVSS: 7.5
Total Vulnerabilities: 3
```

### Manual Test - Full Control

**Step-by-step manual testing:**

```bash
# 1. Test with safe package
python -m agent.main samples/sample_sbom.json

# 2. Test with vulnerable package
python -m agent.main samples/fail_sbom.json

# 3. Test with custom output directory
python -m agent.main samples/fail_sbom.json --output my-scan-results

# 4. View the generated reports
cat my-scan-results/pr_comment.md
cat my-scan-results/report.json
```

## 🚀 GitHub Actions Testing (Automated PR Workflow)

### Step 1: Create a Test Pull Request

You've already pushed `integration-sid` branch. Now create a PR:

**Option A: Via GitHub Web UI**
1. Go to: https://github.com/DivithV25/sbom-repo
2. Click "Compare & pull request" (yellow banner at top)
3. Base: `main` ← Compare: `integration-sid`
4. Click "Create pull request"

**Option B: Via GitHub CLI (if installed)**
```bash
gh pr create --base main --head integration-sid --title "Test: Integrated SBOM Generation and Vulnerability Scanning" --body "Testing the complete PRISM workflow"
```

**Option C: Via URL**
Open this link directly:
```
https://github.com/DivithV25/sbom-repo/compare/main...integration-sid
```

### Step 2: Watch the Workflow Run

**In GitHub Web UI:**
1. After creating PR, go to the "Actions" tab
2. Click on the running workflow "Generate SBOM on PR"
3. Click on job "SBOM Generation & Vulnerability Scan"
4. Watch each step execute in real-time

**Look for this step:**
- "Display Vulnerability Report" - This shows the scan results

### Step 3: View Results in Your VS Code Terminal

You can monitor the GitHub Actions workflow from VS Code using GitHub CLI:

```bash
# Install GitHub CLI first (if not installed)
# Windows: winget install GitHub.cli

# Watch workflow runs
gh run list --branch integration-sid

# View specific run logs (replace RUN_ID with actual ID from list)
gh run view RUN_ID --log

# Or watch the latest run live
gh run watch
```

### Step 4: Check PR Comment

After the workflow completes:
1. Go back to your Pull Request
2. Scroll down to see the automated comment
3. It will show the full vulnerability report

### Step 5: Download Artifacts

From the workflow run page:
1. Scroll to bottom → "Artifacts" section
2. Download:
   - `sbom-pr-X.zip` - Contains the generated SBOM
   - `vulnerability-report-pr-X.zip` - Contains scan results

Extract and view:
```bash
# After downloading
unzip sbom-pr-*.zip
cat pr_comment.md
cat report.json
```

## 🔬 Advanced Testing Scenarios

### Test 3: Add a New Vulnerable Dependency

Create a test branch and modify `package.json`:

```bash
# Create test branch
git checkout -b test-vulnerable-pkg

# Edit package.json to add vulnerable package
# Add this to dependencies: "lodash": "4.17.20"

# Commit and push
git add package.json
git commit -m "test: add vulnerable lodash package"
git push origin test-vulnerable-pkg

# Create PR from test-vulnerable-pkg to main
# Watch the workflow FAIL due to HIGH severity vulnerabilities
```

### Test 4: Test Blocked Package Policy

```bash
# Create another test branch
git checkout integration-sid
git checkout -b test-blocked-pkg

# Create a test SBOM with blocked package
cat > test_blocked.json << 'EOF'
{
  "bomFormat": "CycloneDX",
  "components": [
    {
      "type": "library",
      "name": "openssl",
      "version": "1.0.0"
    }
  ]
}
EOF

# Test locally
python -m agent.main test_blocked.json --rules rules/blocked_packages.yaml

# Expected: FAIL - "Blocked package detected: openssl"
```

## 📊 Understanding the Output

### Terminal Output Format

```
============================================================
🔐 PRISM LOCAL VULNERABILITY SCAN TEST
============================================================

📋 Test: [Test Name]
📂 SBOM: [Path to SBOM file]
------------------------------------------------------------
🔍 Step 1: Loading SBOM...
   Found X component(s)

🔍 Step 2: Scanning for vulnerabilities...
   Checking package@version... Y vulnerabilities found

🔍 Step 3: Computing risk score...
   Max CVSS: X.X
   Severity: [CRITICAL/HIGH/MEDIUM/LOW]
   Total Vulnerabilities: Y

🔍 Step 4: Evaluating policy...
   Decision: [PASS/FAIL]
   Reason: [Explanation]

============================================================
📊 FINAL REPORT
============================================================
[Detailed vulnerability report in markdown format]
============================================================

✅ TEST PASSED - No blocking vulnerabilities
   OR
❌ TEST FAILED - Blocking vulnerabilities detected
============================================================
```

### Exit Codes

- `0` = PASS (safe to merge)
- `1` = FAIL (blocking issues found)

### Risk Levels

| CVSS Score | Severity | Policy Decision |
|------------|----------|-----------------|
| 9.0 - 10.0 | CRITICAL | ❌ FAIL |
| 7.0 - 8.9  | HIGH     | ❌ FAIL |
| 4.0 - 6.9  | MEDIUM   | ✅ PASS |
| 0.0 - 3.9  | LOW      | ✅ PASS |

## 🐛 Troubleshooting

### Issue: "Module not found" error

```bash
# Install dependencies
pip install -r requirements.txt
```

### Issue: "OSV API timeout"

```bash
# The OSV API might be slow or down
# Try again after a few seconds
# Or test with local samples that don't require API
```

### Issue: GitHub Actions workflow not triggering

1. Check if Actions are enabled: Repo Settings → Actions → Allow all actions
2. Verify workflow file exists: `.github/workflows/sbom.yml`
3. Check PR is targeting correct base branch (`main`)

### Issue: No PR comment appearing

1. Check workflow logs for errors
2. Verify token permissions in workflow file
3. Ensure `pull-requests: write` permission is set

## ✨ What Success Looks Like

### Local Test Success:
```
✅ TEST PASSED - No blocking vulnerabilities
```

### GitHub Actions Success:
- ✅ All workflow steps green
- ✅ "Display Vulnerability Report" shows results
- ✅ Automated comment appears on PR
- ✅ Artifacts uploaded successfully

### Failed Scan (Expected for vulnerable packages):
- ❌ "FAIL" decision
- ❌ Lists vulnerabilities with CVSS scores
- ❌ Shows "Severity threshold exceeded"
- ✅ But workflow completes successfully (doesn't crash)

## 📝 Next Steps After Testing

Once you've verified everything works:

1. ✅ Local tests pass/fail correctly
2. ✅ GitHub Actions triggers on PR
3. ✅ Vulnerability scanning completes
4. ✅ PR comments appear
5. ✅ Artifacts are downloadable

You can:
- Merge `integration-sid` into `main` to make this the default behavior
- Create more test cases with different vulnerability scenarios
- Enhance the policy rules
- Add more data sources (NVD, GitHub Advisory, etc.)

## 🎯 Quick Verification Checklist

- [ ] Run `python test_local.py` - Should PASS
- [ ] Run `python test_local.py --vulnerable` - Should FAIL
- [ ] Create PR on GitHub
- [ ] Workflow runs automatically
- [ ] See results in Actions tab
- [ ] PR comment posted with report
- [ ] Downloaded artifacts contain SBOM and report

All checked? **You're ready for the evaluation! 🎉**
