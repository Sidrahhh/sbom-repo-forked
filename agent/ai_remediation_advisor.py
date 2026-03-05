"""
AI-Powered Remediation Advisor

Uses Large Language Models (OpenAI GPT-4) to provide context-aware, intelligent
remediation guidance that goes far beyond simple "upgrade to X.Y.Z" suggestions.

Features:
- Analyzes your actual codebase context
- Reads changelogs to predict breaking changes
- Generates natural language migration guides
- Provides personalized testing strategies
- Explains WHY vulnerabilities matter in YOUR context

This is what differentiates PRISM from Dependabot/Snyk!
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
from agent.config_loader import get_config


class AIRemediationAdvisor:
    """AI-powered vulnerability remediation advisor using LLM"""

    def __init__(self):
        self.config = get_config()
        self.ai_enabled = self.config.is_ai_enabled()
        self.openai_config = self.config.get_openai_config()
        self.ai_features = self.config.get_ai_features()
        self.code_context_config = self.config.get_code_context_config()

        # Check if API key is available
        self.api_key = self.openai_config.get('api_key')
        if not self.api_key and self.ai_enabled:
            print("⚠️  OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
            print(f"⚠️  AI features will be disabled. Using basic remediation instead.")
            self.ai_enabled = False
        elif self.api_key and self.ai_enabled:
            # Mask the key for security (show only last 4 chars)
            masked_key = f"sk-...{self.api_key[-4:]}" if len(self.api_key) > 4 else "***"
            print(f"✓ OpenAI API key detected: {masked_key}")
            print(f"✓ AI model: {self.openai_config.get('model', 'gpt-4')}")

    def generate_remediation_advice(
        self,
        component: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        project_root: Optional[str] = None,
        reachability_analysis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate AI-powered remediation advice.

        Args:
            component: SBOM component with vulnerability
            vulnerabilities: List of vulnerabilities affecting this component
            project_root: Project root for code analysis (optional)
            reachability_analysis: Reachability analysis results (optional)

        Returns:
            {
                "summary": str,  # Executive summary
                "impact_analysis": str,  # How it affects YOUR code
                "remediation_plan": {
                    "steps": [str],
                    "migration_guide": str,
                    "breaking_changes": [str],
                    "testing_strategy": str
                },
                "risk_explanation": str,  # Natural language risk explanation
                "estimated_effort": str,  # Time/effort estimate
                "ai_generated": bool
            }
        """

        if not self.ai_enabled or not self.api_key:
            # Fallback to non-AI remediation
            return self._fallback_remediation(component, vulnerabilities)

        try:
            # Gather context
            context = self._gather_code_context(component, project_root, reachability_analysis)

            # Build prompt
            prompt = self._build_remediation_prompt(component, vulnerabilities, context)

            # Call OpenAI API
            response = self._call_openai_api(prompt)

            # Parse and structure response
            advice = self._parse_ai_response(response)
            advice = self._augment_with_basic_upgrade_fields(advice, component, vulnerabilities)
            advice["ai_generated"] = True

            return advice

        except Exception as e:
            print(f"\n⚠️  AI analysis failed for {component.get('name', 'unknown')}: {type(e).__name__}")
            print(f"    Error details: {str(e)}")
            print(f"    Falling back to basic remediation...\n")
            fallback = self._fallback_remediation(component, vulnerabilities)
            fallback["ai_error"] = str(e)
            return fallback

    def _gather_code_context(
        self,
        component: Dict[str, Any],
        project_root: Optional[str],
        reachability_analysis: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Gather relevant code context for AI analysis"""

        context = {
            "package_name": component.get("name", ""),
            "current_version": component.get("version", ""),
            "ecosystem": self._detect_ecosystem(component),
            "usage_files": [],
            "import_statements": [],
            "code_snippets": [],
            "project_type": None,
            "dependencies_count": 0
        }

        # Add reachability information
        if reachability_analysis:
            context["is_reachable"] = reachability_analysis.get("reachable", True)
            context["reachability_reason"] = reachability_analysis.get("reason", "")

            # Add Level 2 import analysis if available
            if "level_2_import_analysis" in reachability_analysis:
                import_data = reachability_analysis["level_2_import_analysis"]
                context["usage_files"] = [loc["file"] for loc in import_data.get("import_locations", [])]
                context["import_statements"] = [loc["statement"] for loc in import_data.get("import_locations", [])]

        # Gather code snippets if project_root provided
        if project_root and self.ai_features.get('code_analysis', False):
            context.update(self._analyze_project_structure(project_root, component))

        return context

    def _analyze_project_structure(self, project_root: str, component: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze project structure to understand context"""

        project_path = Path(project_root)
        info = {
            "project_type": None,
            "dependencies_count": 0,
            "test_framework": None,
            "code_snippets": []
        }

        # Detect project type
        if (project_path / "package.json").exists():
            info["project_type"] = "Node.js"
            try:
                with open(project_path / "package.json") as f:
                    pkg_json = json.load(f)
                    deps = pkg_json.get("dependencies", {})
                    dev_deps = pkg_json.get("devDependencies", {})
                    info["dependencies_count"] = len(deps) + len(dev_deps)

                    # Detect test framework
                    if "jest" in dev_deps:
                        info["test_framework"] = "Jest"
                    elif "mocha" in dev_deps:
                        info["test_framework"] = "Mocha"
            except:
                pass

        elif (project_path / "requirements.txt").exists():
            info["project_type"] = "Python"
            try:
                with open(project_path / "requirements.txt") as f:
                    info["dependencies_count"] = len(f.readlines())
            except:
                pass

        elif (project_path / "pom.xml").exists():
            info["project_type"] = "Maven (Java)"

        # Find code files that import the vulnerable package
        package_name = component.get("name", "")
        if package_name and info["project_type"] == "Node.js":
            js_files = list(project_path.glob("**/*.js"))[:20]  # Limit to first 20

            for js_file in js_files:
                if self._should_skip_file(js_file):
                    continue

                try:
                    with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                        # Check if file imports the package
                        if package_name in content and ('import' in content or 'require' in content):
                            # Extract relevant snippet (first 10 lines that mention package)
                            lines = content.split('\n')
                            relevant_lines = [
                                line for line in lines[:50]  # First 50 lines
                                if package_name in line or 'import' in line or 'require' in line
                            ][:10]

                            if relevant_lines:
                                info["code_snippets"].append({
                                    "file": str(js_file.relative_to(project_path)),
                                    "snippet": '\n'.join(relevant_lines)
                                })
                except:
                    continue

        return info

    def _build_remediation_prompt(
        self,
        component: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> str:
        """Build comprehensive prompt for OpenAI"""

        # Sort vulnerabilities by severity
        vulns_sorted = sorted(
            vulnerabilities,
            key=lambda v: v.get("cvss", 0.0),
            reverse=True
        )

        # Build vulnerability summary
        vuln_details = []
        for v in vulns_sorted[:5]:  # Top 5 most severe
            vuln_details.append(
                f"- {v.get('id', 'UNKNOWN')}: {v.get('summary', 'No description')}\n"
                f"  CVSS: {v.get('cvss', 0.0)}, Severity: {v.get('severity', 'UNKNOWN')}"
            )

        vuln_summary = '\n'.join(vuln_details)

        # Build code context section
        code_context = ""
        if context.get("usage_files"):
            code_context += f"\nFiles using this package:\n"
            for file in context["usage_files"][:5]:
                code_context += f"- {file}\n"

        if context.get("import_statements"):
            code_context += f"\nImport statements:\n"
            for stmt in context["import_statements"][:5]:
                code_context += f"- {stmt}\n"

        if context.get("code_snippets"):
            code_context += f"\nCode snippets:\n"
            for snippet_data in context["code_snippets"][:2]:
                code_context += f"\nFrom {snippet_data['file']}:\n```\n{snippet_data['snippet']}\n```\n"

        # Build the prompt
        prompt = f"""You are a senior security engineer helping a development team remediate vulnerabilities in their application.

VULNERABILITY CONTEXT:
Package: {context['package_name']}
Current Version: {context['current_version']}
Ecosystem: {context['ecosystem']}
Project Type: {context.get('project_type', 'Unknown')}
Dependencies Count: {context.get('dependencies_count', 0)}
Test Framework: {context.get('test_framework', 'Unknown')}

VULNERABILITIES DETECTED:
{vuln_summary}

REACHABILITY ANALYSIS:
Is Reachable: {context.get('is_reachable', 'Unknown')}
Reason: {context.get('reachability_reason', 'No analysis available')}

CODE CONTEXT:
{code_context if code_context else 'No code context available - package may not be directly imported'}

TASK:
Provide comprehensive, actionable remediation advice in the following format:

1. IMPACT ANALYSIS (2-3 sentences)
   - Explain how these vulnerabilities specifically affect THIS project
   - Mention if vulnerable functions are actually being used (based on code context)
   - Assess real-world risk level for THIS application

2. REMEDIATION PLAN
   - Specific version to upgrade to (research latest stable version)
   - Step-by-step migration instructions
   - Potential breaking changes to watch for
   - Testing strategy tailored to this project

3. RISK EXPLANATION (plain English, non-technical)
   - What could an attacker do?
   - Why does this matter for THIS specific application?
   - Urgency level (immediate, high, medium, low)

4. EFFORT ESTIMATE
   - Time required: X minutes/hours
   - Risk level: Low/Medium/High
   - Confidence: % (based on availability of changelog/migration guides)

Be specific to the code context provided. If the package isn't directly used, mention that this might be a transitive dependency.
Format your response as JSON with keys: impact_analysis, remediation_plan, risk_explanation, estimated_effort"""

        return prompt

    def _call_openai_api(self, prompt: str) -> str:
        """Call OpenAI API with prompt"""

        url = "https://api.openai.com/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.openai_config.get('model', 'gpt-4'),
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert security engineer specializing in vulnerability remediation and secure software development."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": self.openai_config.get('temperature', 0.3),
            "max_tokens": self.openai_config.get('max_tokens', 2000)
        }

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=self.openai_config.get('timeout_seconds', 30)
        )

        if response.status_code != 200:
            error_detail = response.json().get('error', {}).get('message', response.text)
            raise Exception(f"OpenAI API returned {response.status_code}: {error_detail}")

        response.raise_for_status()
        data = response.json()

        return data['choices'][0]['message']['content']

    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured format"""

        try:
            # Try to parse as JSON first
            if '```json' in response:
                # Extract JSON from markdown code block
                json_match = response.split('```json')[1].split('```')[0].strip()
                return json.loads(json_match)
            elif response.strip().startswith('{'):
                return json.loads(response)
            else:
                # Fall back to text parsing
                return {
                    "summary": "AI-generated remediation advice",
                    "impact_analysis": response[:500],
                    "remediation_plan": {
                        "steps": ["See full analysis below"],
                        "migration_guide": response
                    },
                    "risk_explanation": "See impact analysis",
                    "estimated_effort": "Unknown"
                }
        except:
            # If parsing fails, return raw response
            return {
                "summary": "AI-generated remediation advice",
                "full_response": response
            }

    def _fallback_remediation(
        self,
        component: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fallback remediation when AI is not available"""

        from agent.remediation_advisor import generate_remediation_advice as basic_remediation

        # Extract component information
        package_name = component.get('name', 'unknown')
        current_version = component.get('version', 'unknown')
        ecosystem = self._detect_ecosystem(component)
        reachability_info = component.get('reachability', {})

        # Use existing non-AI remediation logic with proper parameters
        basic_advice = basic_remediation(
            package_name=package_name,
            current_version=current_version,
            ecosystem=ecosystem,
            vulnerabilities=vulnerabilities,
            reachability_info=reachability_info
        )

        return {
            "summary": f"Upgrade {package_name} to fix {len(vulnerabilities)} vulnerabilities",
            "impact_analysis": "AI analysis not available - using basic assessment",
            "remediation_plan": basic_advice,
            "risk_explanation": f"This component has {len(vulnerabilities)} known vulnerabilities",
            "estimated_effort": "Unknown",
            "ai_generated": False
        }

    def _augment_with_basic_upgrade_fields(
        self,
        advice: Dict[str, Any],
        component: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fill missing upgrade fields in AI output with deterministic remediation data."""

        from agent.remediation_advisor import generate_remediation_advice as basic_remediation

        package_name = component.get("name", "unknown")
        current_version = component.get("version", "unknown")
        ecosystem = self._detect_ecosystem(component)
        reachability_info = component.get("reachability", {})

        basic_advice = basic_remediation(
            package_name=package_name,
            current_version=current_version,
            ecosystem=ecosystem,
            vulnerabilities=vulnerabilities,
            reachability_info=reachability_info
        )

        plan = advice.get("remediation_plan")
        if not isinstance(plan, dict):
            plan = {} if plan is None else {"steps": [str(plan)]}

        if basic_advice.get("recommended_version") and not plan.get("recommended_version"):
            plan["recommended_version"] = basic_advice["recommended_version"]

        if basic_advice.get("upgrade_command") and not plan.get("upgrade_command"):
            plan["upgrade_command"] = basic_advice["upgrade_command"]

        if basic_advice.get("priority") and not plan.get("priority"):
            plan["priority"] = basic_advice["priority"]

        advice["remediation_plan"] = plan
        return advice

    def _detect_ecosystem(self, component: Dict[str, Any]) -> str:
        """Detect package ecosystem"""
        purl = component.get("purl", "")
        if "npm" in purl:
            return "npm"
        elif "pypi" in purl:
            return "PyPI (pip)"
        elif "maven" in purl:
            return "Maven"
        elif "golang" in purl or "pkg:go" in purl:
            return "Go"
        elif "cargo" in purl:
            return "Cargo (Rust)"
        return "Unknown"

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        exclude_patterns = self.code_context_config.get('exclude_patterns', [])
        file_str = str(file_path)

        for pattern in exclude_patterns:
            pattern_clean = pattern.replace('**/', '').replace('/**', '')
            if pattern_clean in file_str:
                return True
        return False


#  Convenience function
def get_ai_remediation_advice(
    component: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    project_root: Optional[str] = None,
    reachability_analysis: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Quick function to get AI-powered remediation advice.

    Example:
        advice = get_ai_remediation_advice(
            component={"name": "lodash", "version": "4.17.20"},
            vulnerabilities=[{...}],
            project_root="/path/to/project"
        )
    """
    advisor = AIRemediationAdvisor()
    return advisor.generate_remediation_advice(
        component,
        vulnerabilities,
        project_root,
        reachability_analysis
    )


def generate_ai_remediation_summary(
    findings: List[Dict[str, Any]],
    project_root: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Module-level function to generate AI remediation summary for all findings.

    Args:
        findings: List of findings with components and vulnerabilities
        project_root: Project root for code analysis

    Returns:
        List of remediation advice dicts
    """
    advisor = AIRemediationAdvisor()
    remediations = []
    ai_count = 0
    fallback_count = 0

    for finding in findings:
        component = finding.get("component", {})
        vulnerabilities = finding.get("vulnerabilities", [])
        reachability = finding.get("reachability", {})

        if vulnerabilities:
            advice = advisor.generate_remediation_advice(
                component,
                vulnerabilities,
                project_root=project_root,
                reachability_analysis=reachability
            )

            # Track AI vs fallback usage
            if advice.get("ai_generated", False):
                ai_count += 1
            else:
                fallback_count += 1

            remediations.append({
                "component": component,
                "advice": advice
            })

    # Summary
    if ai_count > 0:
        print(f"✓ Generated {ai_count} AI-powered remediation(s)")
    if fallback_count > 0:
        print(f"  Generated {fallback_count} basic remediation(s)")

    return remediations


if __name__ == "__main__":
    # Test AI remediation
    import sys

    print("=== AI Remediation Advisor Test ===\n")

    advisor = AIRemediationAdvisor()
    print(f"AI Enabled: {advisor.ai_enabled}")
    print(f"API Key Available: {'Yes' if advisor.api_key else 'No'}")
    print(f"Model: {advisor.openai_config.get('model', 'N/A')}")

    if advisor.ai_enabled:
        print("\n✅ AI Remediation is ready to use!")
        print("\nTest with:")
        print("  python agent/ai_remediation_advisor.py <package_name> <version>")
    else:
        print("\n⚠️  AI Remediation is not configured.")
        print("   Set OPENAI_API_KEY environment variable to enable.")
