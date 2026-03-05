"""
Automated Dependency Updater for PRISM
Automatically creates PRs for security patches and dependency updates
"""

import requests
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class UpdateRecommendation:
    """Represents an update recommendation"""
    package_name: str
    current_version: str
    recommended_version: str
    update_type: str  # 'security', 'patch', 'minor', 'major'
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    vulnerabilities_fixed: int
    breaking_changes: bool
    confidence: str  # 'HIGH', 'MEDIUM', 'LOW'
    reasoning: str


class AutoUpdater:
    """Automated dependency updater"""
    
    def __init__(self, ecosystem: str = "npm"):
        """
        Initialize auto updater
        
        Args:
            ecosystem: Package ecosystem ('npm', 'pypi', etc.)
        """
        self.ecosystem = ecosystem
        self.registry_urls = {
            'npm': 'https://registry.npmjs.org',
            'pypi': 'https://pypi.org/pypi'
        }
    
    def get_latest_version(self, package_name: str) -> Optional[str]:
        """
        Get latest version of a package from registry
        
        Args:
            package_name: Package name
        
        Returns:
            Latest version string or None
        """
        try:
            if self.ecosystem == 'npm':
                url = f"{self.registry_urls['npm']}/{package_name}/latest"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                return data.get('version')
            
            elif self.ecosystem == 'pypi':
                url = f"{self.registry_urls['pypi']}/{package_name}/json"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                return data.get('info', {}).get('version')
        
        except Exception as e:
            print(f"[UPDATER] Error fetching latest version for {package_name}: {e}")
            return None
    
    def get_all_versions(self, package_name: str) -> List[str]:
        """
        Get all available versions of a package
        
        Args:
            package_name: Package name
        
        Returns:
            List of version strings
        """
        try:
            if self.ecosystem == 'npm':
                url = f"{self.registry_urls['npm']}/{package_name}"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                return list(data.get('versions', {}).keys())
            
            elif self.ecosystem == 'pypi':
                url = f"{self.registry_urls['pypi']}/{package_name}/json"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                return list(data.get('releases', {}).keys())
        
        except Exception as e:
            print(f"[UPDATER] Error fetching versions for {package_name}: {e}")
            return []
    
    def find_security_updates(
        self,
        vulnerabilities: List[Dict[str, Any]],
        current_version: str,
        package_name: str
    ) -> Optional[UpdateRecommendation]:
        """
        Find recommended security update for a vulnerable package
        
        Args:
            vulnerabilities: List of vulnerability dicts
            current_version: Current package version
            package_name: Package name
        
        Returns:
            UpdateRecommendation or None
        """
        if not vulnerabilities:
            return None
        
        # Get available versions
        all_versions = self.get_all_versions(package_name)
        if not all_versions:
            return None
        
        # Sort versions (newest first)
        all_versions = sorted(all_versions, key=self._version_key, reverse=True)
        
        # Determine highest severity
        max_severity = self._get_max_severity(vulnerabilities)
        
        # Find best update target
        latest_version = all_versions[0] if all_versions else None
        
        # Try to find a patch version first (least breaking)
        patch_version = self._find_patch_version(current_version, all_versions)
        
        # Determine which version to recommend
        if patch_version and patch_version != current_version:
            recommended = patch_version
            update_type = 'patch'
            breaking_changes = False
            confidence = 'HIGH'
        elif latest_version and latest_version != current_version:
            recommended = latest_version
            update_type = self._determine_update_type(current_version, latest_version)
            breaking_changes = update_type == 'major'
            confidence = 'MEDIUM' if breaking_changes else 'HIGH'
        else:
            return None
        
        # Create recommendation
        return UpdateRecommendation(
            package_name=package_name,
            current_version=current_version,
            recommended_version=recommended,
            update_type='security',
            severity=max_severity,
            vulnerabilities_fixed=len(vulnerabilities),
            breaking_changes=breaking_changes,
            confidence=confidence,
            reasoning=f"Fixes {len(vulnerabilities)} {max_severity} severity vulnerabilities"
        )
    
    def batch_analyze_updates(
        self,
        components_with_vulns: List[Dict[str, Any]]
    ) -> List[UpdateRecommendation]:
        """
        Analyze multiple components and recommend updates
        
        Args:
            components_with_vulns: List of {component, vulnerabilities} dicts
        
        Returns:
            List of update recommendations
        """
        recommendations = []
        
        for item in components_with_vulns:
            comp = item.get('component', {})
            vulns = item.get('vulnerabilities', [])
            
            package_name = comp.get('name')
            current_version = comp.get('version')
            ecosystem = comp.get('ecosystem', 'npm')
            
            if package_name and current_version:
                # Update ecosystem
                old_ecosystem = self.ecosystem
                self.ecosystem = ecosystem
                
                rec = self.find_security_updates(vulns, current_version, package_name)
                if rec:
                    recommendations.append(rec)
                
                # Restore ecosystem
                self.ecosystem = old_ecosystem
        
        return recommendations
    
    def _get_max_severity(self, vulnerabilities: List[Dict]) -> str:
        """Get maximum severity from vulnerability list"""
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        
        for severity in severity_order:
            for vuln in vulnerabilities:
                # Check if this vulnerability has this severity
                cvss = vuln.get('cvss', 0)
                vuln_severity = self._cvss_to_severity(cvss)
                if vuln_severity == severity:
                    return severity
        
        return 'UNKNOWN'
    
    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity"""
        if cvss >= 9.0:
            return 'CRITICAL'
        elif cvss >= 7.0:
            return 'HIGH'
        elif cvss >= 4.0:
            return 'MEDIUM'
        elif cvss > 0:
            return 'LOW'
        else:
            return 'UNKNOWN'
    
    def _find_patch_version(self, current: str, available: List[str]) -> Optional[str]:
        """Find latest patch version (same major.minor)"""
        try:
            current_parts = self._parse_version(current)
            major, minor = current_parts[0], current_parts[1] if len(current_parts) > 1 else 0
            
            patch_versions = []
            for version in available:
                parts = self._parse_version(version)
                if len(parts) >= 2 and parts[0] == major and parts[1] == minor:
                    patch_versions.append(version)
            
            if patch_versions:
                return sorted(patch_versions, key=self._version_key, reverse=True)[0]
        
        except Exception:
            pass
        
        return None
    
    def _determine_update_type(self, old: str, new: str) -> str:
        """Determine update type (major, minor, patch)"""
        try:
            old_parts = self._parse_version(old)
            new_parts = self._parse_version(new)
            
            if len(old_parts) >= 1 and len(new_parts) >= 1:
                if new_parts[0] > old_parts[0]:
                    return 'major'
                elif len(old_parts) >= 2 and len(new_parts) >= 2 and new_parts[1] > old_parts[1]:
                    return 'minor'
                else:
                    return 'patch'
        
        except Exception:
            pass
        
        return 'unknown'
    
    def _parse_version(self, version: str) -> List[int]:
        """Parse semantic version"""
        version = version.lstrip('v').split('-')[0]
        parts = []
        for part in version.split('.'):
            try:
                parts.append(int(part))
            except ValueError:
                pass
        return parts
    
    def _version_key(self, version: str) -> Tuple[int, ...]:
        """Generate sortable version key"""
        parts = self._parse_version(version)
        # Pad with zeros to ensure consistent length for sorting
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    
    def format_recommendations_markdown(self, recommendations: List[UpdateRecommendation]) -> str:
        """
        Format update recommendations as markdown
        
        Args:
            recommendations: List of UpdateRecommendation objects
        
        Returns:
            Markdown-formatted string
        """
        if not recommendations:
            return "## 🔄 Automated Update Recommendations\n\n*No security updates available.*\n"
        
        lines = []
        lines.append("## 🔄 Automated Update Recommendations\n")
        lines.append(f"\n**{len(recommendations)} security update(s) available**\n")
        
        # Group by severity
        critical = [r for r in recommendations if r.severity == 'CRITICAL']
        high = [r for r in recommendations if r.severity == 'HIGH']
        medium = [r for r in recommendations if r.severity == 'MEDIUM']
        low = [r for r in recommendations if r.severity == 'LOW']
        
        if critical:
            lines.append("\n### 🔴 Critical Updates (Apply Immediately)\n")
            for rec in critical:
                lines.append(self._format_recommendation(rec))
        
        if high:
            lines.append("\n### 🟠 High Priority Updates\n")
            for rec in high:
                lines.append(self._format_recommendation(rec))
        
        if medium:
            lines.append("\n### 🟡 Medium Priority Updates\n")
            for rec in medium:
                lines.append(self._format_recommendation(rec))
        
        if low:
            lines.append("\n### 🟢 Low Priority Updates\n")
            for rec in low:
                lines.append(self._format_recommendation(rec))
        
        return ''.join(lines)
    
    def _format_recommendation(self, rec: UpdateRecommendation) -> str:
        """Format single recommendation"""
        lines = []
        lines.append(f"\n**`{rec.package_name}`**: {rec.current_version} → {rec.recommended_version}\n")
        lines.append(f"- Fixes: {rec.vulnerabilities_fixed} vulnerabilities\n")
        lines.append(f"- Type: {rec.update_type.title()}\n")
        lines.append(f"- Breaking changes: {'Yes' if rec.breaking_changes else 'No'}\n")
        lines.append(f"- Confidence: {rec.confidence}\n")
        lines.append(f"- Reasoning: {rec.reasoning}\n")
        
        return ''.join(lines)
