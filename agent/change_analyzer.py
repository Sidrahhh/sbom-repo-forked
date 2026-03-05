"""
Change Analyzer for PRISM
Analyzes dependency changes for security and risk implications
"""

from typing import Dict, List, Any
from agent.sbom_differ import DependencyChange


class ChangeAnalyzer:
    """Analyze dependency changes for security implications"""
    
    def __init__(self, vulnerability_scanner=None):
        """
        Initialize change analyzer
        
        Args:
            vulnerability_scanner: Function to scan for vulnerabilities
        """
        self.scanner = vulnerability_scanner
    
    def analyze_change_risk(
        self,
        change: DependencyChange,
        old_vulns: List[Dict] = None,
        new_vulns: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Analyze risk of a single dependency change
        
        Args:
            change: DependencyChange object
            old_vulns: Vulnerabilities in old version (optional)
            new_vulns: Vulnerabilities in new version (optional)
        
        Returns:
            Risk analysis dict
        """
        risk_level = "LOW"
        risk_factors = []
        recommendation = "No action required"
        
        if change.change_type == 'added':
            risk_level = "MEDIUM"
            risk_factors.append("New dependency introduces supply chain risk")
            recommendation = "Review dependency necessity and maintainer reputation"
            
            if new_vulns:
                risk_level = "HIGH"
                risk_factors.append(f"New dependency has {len(new_vulns)} known vulnerabilities")
                recommendation = "Consider alternative package or upgrade to secure version"
        
        elif change.change_type == 'removed':
            risk_level = "LOW"
            risk_factors.append("Dependency removed - reduces attack surface")
            recommendation = "Verify no breaking changes in application"
        
        elif change.change_type == 'upgraded':
            # Upgrading is generally positive
            risk_level = "LOW"
            
            # Check if upgrade fixes vulnerabilities
            old_vuln_count = len(old_vulns) if old_vulns else 0
            new_vuln_count = len(new_vulns) if new_vulns else 0
            
            if old_vuln_count > new_vuln_count:
                risk_factors.append(f"Upgrade fixes {old_vuln_count - new_vuln_count} vulnerabilities ✓")
                recommendation = "Good security practice - approve upgrade"
            elif new_vuln_count > old_vuln_count:
                risk_level = "HIGH"
                risk_factors.append(f"Upgrade introduces {new_vuln_count - old_vuln_count} new vulnerabilities")
                recommendation = "Review new vulnerabilities before merging"
            else:
                risk_factors.append("Version upgrade - may include bug fixes and features")
                recommendation = "Test for breaking changes"
            
            # Check for major version bump (potentially breaking)
            if self._is_major_version_bump(change.old_version, change.new_version):
                risk_level = "MEDIUM" if risk_level == "LOW" else risk_level
                risk_factors.append("Major version upgrade - may contain breaking changes")
                recommendation = "Review changelog and test thoroughly"
        
        elif change.change_type == 'downgraded':
            risk_level = "HIGH"
            risk_factors.append("Version downgrade - unusual and potentially risky")
            recommendation = "Investigate reason for downgrade"
            
            old_vuln_count = len(old_vulns) if old_vulns else 0
            new_vuln_count = len(new_vulns) if new_vulns else 0
            
            if new_vuln_count > old_vuln_count:
                risk_factors.append(f"Downgrade reintroduces {new_vuln_count - old_vuln_count} vulnerabilities")
                recommendation = "Block merge - security regression detected"
        
        return {
            "change": change.to_dict(),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendation": recommendation,
            "old_vulnerability_count": len(old_vulns) if old_vulns else 0,
            "new_vulnerability_count": len(new_vulns) if new_vulns else 0
        }
    
    def analyze_all_changes(
        self,
        changes: Dict[str, List[DependencyChange]],
        scan_vulnerabilities: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze all dependency changes
        
        Args:
            changes: Changes dict from SBOMDiffer
            scan_vulnerabilities: Whether to scan for vulnerabilities
        
        Returns:
            Comprehensive analysis dict
        """
        analysis_results = {
            'added': [],
            'removed': [],
            'upgraded': [],
            'downgraded': []
        }
        
        overall_risk = "LOW"
        high_risk_changes = 0
        
        # Analyze each change type
        for change_type in ['added', 'removed', 'upgraded', 'downgraded']:
            for change in changes.get(change_type, []):
                old_vulns = []
                new_vulns = []
                
                # Scan for vulnerabilities if requested and scanner available
                if scan_vulnerabilities and self.scanner:
                    try:
                        if change.old_version:
                            old_vulns = self.scanner(
                                change.name,
                                change.old_version,
                                change.ecosystem
                            )
                        if change.new_version:
                            new_vulns = self.scanner(
                                change.name,
                                change.new_version,
                                change.ecosystem
                            )
                    except Exception as e:
                        print(f"[ANALYZER] Error scanning {change.name}: {e}")
                
                # Analyze this change
                analysis = self.analyze_change_risk(change, old_vulns, new_vulns)
                analysis_results[change_type].append(analysis)
                
                # Track high-risk changes
                if analysis['risk_level'] == 'HIGH':
                    high_risk_changes += 1
        
        # Determine overall risk
        if high_risk_changes > 0:
            overall_risk = "HIGH"
        elif high_risk_changes > 0 or len(changes.get('added', [])) > 0:
            overall_risk = "MEDIUM"
        
        return {
            'analysis': analysis_results,
            'overall_risk': overall_risk,
            'high_risk_count': high_risk_changes,
            'total_changes': sum(len(v) for v in changes.values() if isinstance(v, list))
        }
    
    def _is_major_version_bump(self, old_version: str, new_version: str) -> bool:
        """
        Check if upgrade is a major version bump
        
        Args:
            old_version: Old version
            new_version: New version
        
        Returns:
            True if major version changed
        """
        try:
            old_major = int(old_version.lstrip('v').split('.')[0])
            new_major = int(new_version.lstrip('v').split('.')[0])
            return new_major > old_major
        except (ValueError, IndexError):
            return False
    
    def format_analysis_markdown(self, analysis: Dict[str, Any]) -> str:
        """
        Format analysis as markdown
        
        Args:
            analysis: Analysis dict from analyze_all_changes()
        
        Returns:
            Markdown-formatted string
        """
        lines = []
        
        lines.append("## 🔍 Dependency Change Risk Analysis\n")
        lines.append(f"\n**Overall Risk Level:** {self._risk_badge(analysis['overall_risk'])}\n")
        lines.append(f"**High-Risk Changes:** {analysis['high_risk_count']}\n")
        lines.append(f"**Total Changes:** {analysis['total_changes']}\n")
        
        # Group by risk level
        high_risk_items = []
        medium_risk_items = []
        low_risk_items = []
        
        for change_type, items in analysis['analysis'].items():
            for item in items:
                if item['risk_level'] == 'HIGH':
                    high_risk_items.append(item)
                elif item['risk_level'] == 'MEDIUM':
                    medium_risk_items.append(item)
                else:
                    low_risk_items.append(item)
        
        # Show high-risk changes first
        if high_risk_items:
            lines.append("\n### ⚠️ High-Risk Changes (Requires Review)\n")
            for item in high_risk_items:
                lines.append(self._format_change_item(item))
        
        if medium_risk_items:
            lines.append("\n### ⚡ Medium-Risk Changes\n")
            for item in medium_risk_items:
                lines.append(self._format_change_item(item))
        
        if low_risk_items and len(low_risk_items) <= 5:
            lines.append("\n### ✅ Low-Risk Changes\n")
            for item in low_risk_items:
                lines.append(self._format_change_item(item))
        elif low_risk_items:
            lines.append(f"\n### ✅ Low-Risk Changes ({len(low_risk_items)} items)\n")
            lines.append("*All low-risk changes passed automatic review.*\n")
        
        return ''.join(lines)
    
    def _format_change_item(self, item: Dict[str, Any]) -> str:
        """Format a single change item"""
        change = item['change']
        lines = []
        
        # Header
        if change['change_type'] == 'added':
            lines.append(f"\n**`{change['name']}@{change['new_version']}` (Added)**\n")
        elif change['change_type'] == 'removed':
            lines.append(f"\n**`{change['name']}@{change['old_version']}` (Removed)**\n")
        elif change['change_type'] in ['upgraded', 'downgraded']:
            lines.append(f"\n**`{change['name']}`: {change['old_version']} → {change['new_version']}**\n")
        
        # Vulnerability info
        if item['old_vulnerability_count'] > 0 or item['new_vulnerability_count'] > 0:
            lines.append(f"- Vulnerabilities: {item['old_vulnerability_count']} → {item['new_vulnerability_count']}\n")
        
        # Risk factors
        for factor in item['risk_factors']:
            lines.append(f"- {factor}\n")
        
        # Recommendation
        lines.append(f"- **Recommendation:** {item['recommendation']}\n")
        
        return ''.join(lines)
    
    def _risk_badge(self, risk_level: str) -> str:
        """Get emoji badge for risk level"""
        badges = {
            'HIGH': '🔴 HIGH',
            'MEDIUM': '🟡 MEDIUM',
            'LOW': '🟢 LOW'
        }
        return badges.get(risk_level, risk_level)
