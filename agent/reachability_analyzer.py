"""
Reachability Analyzer - Determines if vulnerable code is actually reachable

Level 1 Implementation:
- Checks dependency scope (optional/excluded → unreachable)
- Checks dev vs production dependencies
- Analyzes package properties from SBOM

Level 2 Implementation:
- Import graph analysis (is package actually imported?)
- Call graph analysis (are vulnerable functions called?)
- Function-level precision
"""

from typing import Dict, List, Any, Optional
from agent.config_loader import get_config


# Level 2 analyzers (imported conditionally to avoid circular dependencies)
_import_graph_analyzer = None
_call_graph_analyzer = None


def _get_import_analyzer(project_root: str):
    """Lazy load import graph analyzer"""
    global _import_graph_analyzer
    if _import_graph_analyzer is None:
        from agent.import_graph_analyzer import ImportGraphAnalyzer
        _import_graph_analyzer = ImportGraphAnalyzer(project_root)
    return _import_graph_analyzer


def _get_call_analyzer(project_root: str):
    """Lazy load call graph analyzer"""
    global _call_graph_analyzer
    if _call_graph_analyzer is None:
        from agent.call_graph_analyzer import CallGraphAnalyzer
        _call_graph_analyzer = CallGraphAnalyzer(project_root)
    return _call_graph_analyzer


def analyze_reachability(
    component: Dict[str, Any],
    sbom_data: Dict[str, Any],
    project_root: Optional[str] = None,
    enable_level_2: bool = False
) -> Dict[str, Any]:
    """
    Analyze if a component's code is reachable in the application.

    Args:
        component: Component dict from SBOM with name, version, purl, etc.
        sbom_data: Full SBOM JSON for context (dependency tree, metadata)

    Returns:
        {
            "reachable": bool,
            "confidence": str,  # "high", "medium", "low"
            "reason": str,
            "scope": str,       # "required", "optional", "excluded", "unknown"
            "is_dev_only": bool
        }
    """

    result = {
        "reachable": True,  # Default to reachable (fail-safe)
        "confidence": "low",
        "reason": "No scope information available - assuming reachable",
        "scope": "unknown",
        "is_dev_only": False
    }

    # Check 1: Scope field (CycloneDX standard)
    scope = component.get("scope", "").lower()
    if scope:
        result["scope"] = scope

        if scope in ["optional", "excluded"]:
            result["reachable"] = False
            result["confidence"] = "high"
            result["reason"] = f"Dependency scope is '{scope}' - not included in runtime"
            return result

        elif scope == "required":
            result["reachable"] = True
            result["confidence"] = "medium"
            result["reason"] = "Dependency scope is 'required' - likely reachable"

    # Check 2: Properties array for dev dependency markers
    properties = component.get("properties", [])
    for prop in properties:
        name = prop.get("name", "")
        value = prop.get("value", "")

        # npm: check if it's a devDependency
        if name == "cdx:npm:package:development" and value == "true":
            result["is_dev_only"] = True
            result["reachable"] = False
            result["confidence"] = "high"
            result["reason"] = "Package is a devDependency - not included in production"
            return result

        # Maven: check scope
        if name == "cdx:maven:scope" and value in ["test", "provided"]:
            result["is_dev_only"] = True
            result["reachable"] = False
            result["confidence"] = "high"
            result["reason"] = f"Maven scope is '{value}' - not in runtime classpath"
            return result

    # Check 3: Component type
    comp_type = component.get("type", "").lower()
    if comp_type in ["build-tool", "dev-dependency", "test-dependency"]:
        result["is_dev_only"] = True
        result["reachable"] = False
        result["confidence"] = "medium"
        result["reason"] = f"Component type '{comp_type}' indicates development-only"
        return result

    # Check 4: Analyze dependency relationships (if available)
    # This requires dependency graph - future enhancement
    dependencies = sbom_data.get("dependencies", [])
    if dependencies:
        # TODO: Implement dependency tree analysis
        # For now, just note that we have dependency data
        result["confidence"] = "medium"
        result["reason"] = "Dependency is explicitly listed - likely used in code"

    # Level 2: Code-level analysis (if enabled and project_root provided)
    cfg = get_config()
    if enable_level_2 and project_root and cfg.is_level_2_reachability_enabled():
        package_name = component.get("name", "")

        if package_name:
            # Detect language from SBOM or component type
            language = detect_language_from_component(component, sbom_data)

            try:
                # Import graph analysis
                import_analyzer = _get_import_analyzer(project_root)
                import_result = import_analyzer.analyze_package_usage(package_name, language)

                if not import_result['is_imported']:
                    # Package not imported anywhere - definitely unreachable
                    result["reachable"] = False
                    result["confidence"] = "high"
                    result["reason"] = f"Level 2: Package '{package_name}' is not imported in any source file"
                    result["level_2_import_analysis"] = import_result
                    return result

                elif import_result['is_imported'] and import_result['confidence'] >= 0.8:
                    # Package is clearly imported - reachable
                    result["reachable"] = True
                    result["confidence"] = "high"
                    result["reason"] = f"Level 2: Package '{package_name}' is imported in {import_result['usage_count']} file(s)"
                    result["level_2_import_analysis"] = import_result

            except Exception as e:
                # Level 2 failed, fallback to Level 1
                result["level_2_error"] = str(e)

    return result


def calculate_reachability_score(reachability_result: Dict[str, Any]) -> float:
    """
    Convert reachability analysis to numeric score for risk calculation.

    Score ranges:
    - 0.0: Definitely unreachable (excluded, dev-only)
    - 0.3: Probably unreachable (low confidence)
    - 0.7: Probably reachable (medium confidence)
    - 1.0: Definitely reachable (high confidence)

    Args:
        reachability_result: Output from analyze_reachability()

    Returns:
        float: Reachability score between 0.0 and 1.0
    """

    if not reachability_result["reachable"]:
        # Unreachable - low risk multiplier
        if reachability_result["confidence"] == "high":
            return 0.0
        elif reachability_result["confidence"] == "medium":
            return 0.2
        else:
            return 0.3
    else:
        # Reachable - high risk multiplier
        if reachability_result["confidence"] == "high":
            return 1.0
        elif reachability_result["confidence"] == "medium":
            return 0.7
        else:
            return 0.5  # Unknown/low confidence - assume moderately reachable


def analyze_all_components(
    sbom_data: Dict[str, Any],
    project_root: Optional[str] = None,
    enable_level_2: bool = True
) -> Dict[str, Dict[str, Any]]:
    """
    Analyze reachability for all components in SBOM.

    Args:
        sbom_data: Full SBOM JSON
        project_root: Path to project root for Level 2 analysis
        enable_level_2: Enable code-based reachability analysis

    Returns:
        Dict mapping component key (name@version) to reachability result
    """

    results = {}
    components = sbom_data.get("components", [])

    for component in components:
        name = component.get("name", "unknown")
        version = component.get("version", "unknown")
        key = f"{name}@{version}"

        results[key] = analyze_reachability(
            component,
            sbom_data,
            project_root=project_root,
            enable_level_2=enable_level_2
        )

    return results


def enhance_findings_with_reachability(
    findings: List[Dict[str, Any]],
    reachability_data: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Add reachability information to vulnerability findings.

    Args:
        findings: List of findings, each with {"component": {...}, "vulnerabilities": [...]}
        reachability_data: Output from analyze_all_components()

    Returns:
        Enhanced findings with reachability info added to each vulnerability
    """

    enhanced_findings = []

    for finding in findings:
        component = finding.get("component", {})
        pkg = component.get("name", "unknown")
        version = component.get("version", "unknown")
        key = f"{pkg}@{version}"

        # Get reachability data for this component
        reach = reachability_data.get(key, {
            "reachable": True,
            "confidence": "low",
            "reason": "Component not found in reachability analysis",
            "scope": "unknown",
            "is_dev_only": False
        })

        # Add reachability to component level
        component["reachability"] = reach
        component["reachability_score"] = calculate_reachability_score(reach)

        # Also add to each vulnerability for convenience
        vulnerabilities = finding.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            vuln["reachability"] = reach
            vuln["reachability_score"] = calculate_reachability_score(reach)

        enhanced_findings.append({
            "component": component,
            "vulnerabilities": vulnerabilities
        })

    return enhanced_findings


def detect_language_from_component(component: Dict[str, Any], sbom_data: Dict[str, Any]) -> str:
    """
    Detect programming language from component metadata.

    Args:
        component: SBOM component
        sbom_data: Full SBOM for context

    Returns:
        Language name: "javascript", "python", "java", etc.
    """

    # Check purl (package URL) for ecosystem
    purl = component.get("purl", "")
    if "pkg:npm" in purl:
        return "javascript"
    elif "pkg:pypi" in purl:
        return "python"
    elif "pkg:maven" in purl or "pkg:gradle" in purl:
        return "java"
    elif "pkg:golang" in purl or "pkg:go" in purl:
        return "go"
    elif "pkg:cargo" in purl:
        return "rust"
    elif "pkg:nuget" in purl:
        return "csharp"
    elif "pkg:gem" in purl or "pkg:rubygems" in purl:
        return "ruby"
    elif "pkg:composer" in purl:
        return "php"

    # Check SBOM metadata for project language
    metadata = sbom_data.get("metadata", {})
    comp_metadata = metadata.get("component", {})

    # Some SBOMs include language in component type
    comp_type = comp_metadata.get("type", "").lower()
    if "javascript" in comp_type or "node" in comp_type:
        return "javascript"
    elif "python" in comp_type:
        return "python"

    # Default to JavaScript for npm packages, Python for pip
    properties = component.get("properties", [])
    for prop in properties:
        if "npm" in prop.get("name", "").lower():
            return "javascript"
        elif "pip" in prop.get("name", "").lower() or "python" in prop.get("name", "").lower():
            return "python"

    # Final fallback
    return "javascript"  # Most common in web projects


def analyze_vulnerable_function_calls(
    component: Dict[str, Any],
    vulnerability: Dict[str, Any],
    project_root: str,
    vulnerable_functions: List[str] = None
) -> Dict[str, Any]:
    """
    Level 2: Analyze if specific vulnerable functions are actually called.

    Args:
        component: SBOM component
        vulnerability: Vulnerability dict with CVE ID
        project_root: Project root directory
        vulnerable_functions: List of vulnerable function names

    Returns:
        Call graph analysis result with confidence score
    """

    package_name = component.get("name", "")
    cve_id = vulnerability.get("id", "")

    if not vulnerable_functions:
        # Try to get from known database
        from agent.call_graph_analyzer import get_vulnerable_functions_for_cve
        vulnerable_functions = get_vulnerable_functions_for_cve(package_name, cve_id)

    if not vulnerable_functions:
        # No known vulnerable functions - assume vulnerability is in any usage
        return {
            "is_vulnerable_function_called": None,
            "confidence": 0.5,
            "summary": "No specific vulnerable functions known - generic package vulnerability"
        }

    # Detect language
    language = detect_language_from_component(component, {})

    try:
        call_analyzer = _get_call_analyzer(project_root)
        result = call_analyzer.analyze_vulnerable_function_usage(
            package_name,
            vulnerable_functions,
            language
        )
        return result
    except Exception as e:
        return {
            "is_vulnerable_function_called": None,
            "confidence": 0.5,
            "summary": f"Call graph analysis failed: {str(e)}",
            "error": str(e)
        }

