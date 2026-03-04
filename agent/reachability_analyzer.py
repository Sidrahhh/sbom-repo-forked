"""
Reachability Analyzer - Determines if vulnerable code is actually reachable

Level 1 Implementation:
- Checks dependency scope (optional/excluded → unreachable)
- Checks dev vs production dependencies
- Analyzes package properties from SBOM

Level 2 (Future):
- Static code analysis (import parsing)
- Call graph analysis
- Dead code detection
"""

from typing import Dict, List, Any


def analyze_reachability(component: Dict[str, Any], sbom_data: Dict[str, Any]) -> Dict[str, Any]:
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


def analyze_all_components(sbom_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Analyze reachability for all components in SBOM.
    
    Args:
        sbom_data: Full SBOM JSON
    
    Returns:
        Dict mapping component key (name@version) to reachability result
    """
    
    results = {}
    components = sbom_data.get("components", [])
    
    for component in components:
        name = component.get("name", "unknown")
        version = component.get("version", "unknown")
        key = f"{name}@{version}"
        
        results[key] = analyze_reachability(component, sbom_data)
    
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
