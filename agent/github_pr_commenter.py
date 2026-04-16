"""
GitHub PR Review Commenter

Posts inline review comments on specific lines of changed files,
suggesting remediation fixes for vulnerabilities found in dependencies.

Features:
- Analyzes diff to find dependency lines
- Posts inline comments with suggested safe versions
- Groups comments by file for efficiency
- Uses GitHub's review API (not comment API)
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path


def find_dependency_line_in_diff(diff_content: str, package_name: str, current_version: str) -> Optional[int]:
    """
    Find the line position of a dependency in a diff.
    
    This searches for the package name and version pattern in the diff
    and returns the position (1-indexed line number in the diff snippet).
    
    Args:
        diff_content: The unified diff content for the file
        package_name: Name of the package to find
        current_version: Current version of the package
        
    Returns:
        Line position (1-indexed) or None if not found
    """
    lines = diff_content.split('\n')
    position = -1
    
    for line in lines:
        position += 1
        
        # Only consider added/changed lines (start with + or context lines)
        if line.startswith('@@'):
            continue
        if line.startswith('-'):
            continue
            
        # Look for the package in the line (with quotes for JSON format)
        if package_name in line:
            # Check if current version is also in the line (for JSON format: "package": "version")
            if f'"{current_version}"' in line or f"'{current_version}'" in line:
                return position
            # For loose matching (in case version format differs)
            if current_version in line:
                return position
    
    return None


def generate_review_comment(
    package_name: str,
    current_version: str,
    recommended_version: str,
    ecosystem: str,
    upgrade_command: str = None,
    explanation: str = None
) -> str:
    """
    Generate a review comment suggesting a safer version.
    
    Args:
        package_name: Package name
        current_version: Current (vulnerable) version
        recommended_version: Recommended safe version
        ecosystem: Ecosystem (npm, pypi, maven, etc.)
        upgrade_command: Optional upgrade command to show
        explanation: Optional explanation of why this version is recommended
        
    Returns:
        Markdown-formatted review comment
    """
    comment = f"✅ **Vulnerability Fix Available**\n\n"
    comment += f"Package `{package_name}` has known vulnerabilities.\n\n"
    comment += f"**Current Version:** `{current_version}`\n"
    comment += f"**Recommended Version:** `{recommended_version}`\n\n"
    
    if explanation:
        comment += f"**Why:** {explanation}\n\n"
    
    if upgrade_command:
        comment += f"**Upgrade command:**\n```bash\n{upgrade_command}\n```\n\n"
    else:
        # Generate generic command if not provided
        if ecosystem.lower() == "npm":
            cmd = f"npm install {package_name}@{recommended_version}"
        elif ecosystem.lower() in ("pypi", "pypi (pip)"):
            cmd = f"pip install {package_name}=={recommended_version}"
        elif ecosystem.lower() == "maven":
            cmd = f"Update pom.xml to version {recommended_version}"
        else:
            cmd = f"Upgrade {package_name} to {recommended_version}"
        
        comment += f"**Upgrade command:**\n```{ecosystem.lower()}\n{cmd}\n```\n\n"
    
    comment += f"💡 **Note:** This is a patch version upgrade (safe to apply). Always run tests after updating dependencies."
    
    return comment


def build_review_comments(
    findings: List[Dict[str, Any]],
    remediations: List[Dict[str, Any]],
    diff_data: Dict[str, str]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Build review comments structured for GitHub review API.
    
    Args:
        findings: List of vulnerability findings
        remediations: List of remediation recommendations
        diff_data: Dictionary mapping file paths to their unified diff content
                   e.g., {"package.json": "diff content here"}
                   
    Returns:
        Dictionary mapping file paths to lists of review comments:
        {
            "package.json": [
                {
                    "path": "package.json",
                    "position": 6,
                    "body": "comment text"
                }
            ]
        }
    """
    review_comments = {}
    
    # Create a lookup for remediations by component name
    remediation_map = {}
    for remediation in remediations:
        comp = remediation.get("component", {})
        comp_name = comp.get("name")
        if comp_name:
            remediation_map[comp_name] = remediation
    
    # Process each finding with vulnerabilities
    for finding in findings:
        if not finding.get("vulnerabilities"):
            continue
        
        comp = finding.get("component", {})
        comp_name = comp.get("name")
        comp_version = comp.get("version")
        ecosystem = comp.get("ecosystem", "npm")
        
        if not comp_name or comp_name not in remediation_map:
            continue
        
        remediation = remediation_map[comp_name]
        advice = remediation.get("advice", {})
        recommended_version = advice.get("recommended_version")
        
        if not recommended_version:
            continue
        
        upgrade_command = advice.get("upgrade_command")
        explanation = advice.get("summary")
        
        # Generate comment
        comment_text = generate_review_comment(
            comp_name,
            comp_version,
            recommended_version,
            ecosystem,
            upgrade_command,
            explanation
        )
        
        # Find which file contains this dependency
        # Typically package.json for npm, requirements.txt for PyPI, pom.xml for Maven
        target_file = _get_dependency_file_for_ecosystem(ecosystem)
        
        if target_file not in diff_data:
            continue
        
        diff_content = diff_data[target_file]
        line_position = find_dependency_line_in_diff(diff_content, comp_name, comp_version)
        
        if not line_position:
            continue
        
        # Add to review comments
        if target_file not in review_comments:
            review_comments[target_file] = []
        
        review_comments[target_file].append({
            "path": target_file,
            "position": line_position,
            "body": comment_text
        })
    
    return review_comments


def _get_dependency_file_for_ecosystem(ecosystem: str) -> str:
    """Get the main dependency file for a given ecosystem."""
    ecosystem_lower = (ecosystem or "").lower()
    
    if ecosystem_lower == "npm":
        return "package.json"
    elif ecosystem_lower in ("pypi", "pypi (pip)"):
        return "requirements.txt"
    elif ecosystem_lower == "maven":
        return "pom.xml"
    elif ecosystem_lower == "go":
        return "go.mod"
    elif ecosystem_lower == "rubygems":
        return "Gemfile"
    elif ecosystem_lower == "cargo":
        return "Cargo.toml"
    elif ecosystem_lower == "nuget":
        return "packages.config"
    else:
        return "package.json"  # Default fallback


def generate_github_review_payload(
    review_comments: Dict[str, List[Dict[str, Any]]],
    commit_sha: str
) -> Dict[str, Any]:
    """
    Generate payload for GitHub's create review API.
    
    Args:
        review_comments: Review comments structured by file
        commit_sha: The commit SHA to review
        
    Returns:
        Payload for github.rest.pulls.createReview
    """
    # Flatten review comments into a single list
    all_comments = []
    for file_comments in review_comments.values():
        all_comments.extend(file_comments)
    
    if not all_comments:
        return None
    
    return {
        "commit_id": commit_sha,
        "body": "🔍 PRISM Security Scan: Suggested vulnerability fixes",
        "comments": all_comments,
        "event": "COMMENT"  # Use COMMENT instead of REQUEST_CHANGES to avoid blocking
    }


# Export for use in GitHub Actions workflow
if __name__ == "__main__":
    print("This module is meant to be imported by the reporter and GitHub Actions workflow.")
