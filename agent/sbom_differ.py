"""
SBOM Differ for PRISM
Compares two SBOMs and identifies changes in dependencies
"""

from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class DependencyChange:
    """Represents a change in a dependency"""
    name: str
    change_type: str  # 'added', 'removed', 'upgraded', 'downgraded'
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    ecosystem: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def __str__(self) -> str:
        """String representation"""
        if self.change_type == 'added':
            return f"🟢 {self.name}@{self.new_version} (new)"
        elif self.change_type == 'removed':
            return f"🔴 {self.name}@{self.old_version} (removed)"
        elif self.change_type == 'upgraded':
            return f"🔵 {self.name}: {self.old_version} → {self.new_version} (upgraded)"
        elif self.change_type == 'downgraded':
            return f"🟡 {self.name}: {self.old_version} → {self.new_version} (downgraded)"
        else:
            return f"{self.name}"


class SBOMDiffer:
    """Compare two SBOMs and identify changes"""
    
    def __init__(self):
        pass
    
    def _normalize_component_key(self, component: Dict[str, Any]) -> str:
        """Generate normalized key for a component"""
        name = component.get("name", "")
        # Remove version for key - we want to track version changes
        return name.lower().strip()
    
    def _extract_components(self, sbom: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Extract components from SBOM
        
        Args:
            sbom: SBOM dictionary (CycloneDX format)
        
        Returns:
            Dict mapping component names to component dicts
        """
        components = {}
        
        # Handle CycloneDX format
        if "components" in sbom:
            for comp in sbom.get("components", []):
                key = self._normalize_component_key(comp)
                components[key] = comp
        
        return components
    
    def compare(
        self,
        old_sbom: Dict[str, Any],
        new_sbom: Dict[str, Any]
    ) -> Dict[str, List[DependencyChange]]:
        """
        Compare two SBOMs and identify changes
        
        Args:
            old_sbom: Previous SBOM
            new_sbom: Current SBOM
        
        Returns:
            Dictionary with lists of changes by type:
            {
                'added': [...],
                'removed': [...],
                'upgraded': [...],
                'downgraded': [...],
                'unchanged': [...]
            }
        """
        old_comps = self._extract_components(old_sbom)
        new_comps = self._extract_components(new_sbom)
        
        changes = {
            'added': [],
            'removed': [],
            'upgraded': [],
            'downgraded': [],
            'unchanged': []
        }
        
        # Find added and changed components
        for key, new_comp in new_comps.items():
            new_version = new_comp.get("version", "")
            ecosystem = new_comp.get("ecosystem")
            
            if key not in old_comps:
                # New component
                changes['added'].append(DependencyChange(
                    name=new_comp.get("name"),
                    change_type='added',
                    new_version=new_version,
                    ecosystem=ecosystem
                ))
            else:
                # Existing component - check version
                old_version = old_comps[key].get("version", "")
                
                if old_version != new_version:
                    # Version changed
                    if self._is_upgrade(old_version, new_version):
                        changes['upgraded'].append(DependencyChange(
                            name=new_comp.get("name"),
                            change_type='upgraded',
                            old_version=old_version,
                            new_version=new_version,
                            ecosystem=ecosystem
                        ))
                    else:
                        changes['downgraded'].append(DependencyChange(
                            name=new_comp.get("name"),
                            change_type='downgraded',
                            old_version=old_version,
                            new_version=new_version,
                            ecosystem=ecosystem
                        ))
                else:
                    # Unchanged
                    changes['unchanged'].append(DependencyChange(
                        name=new_comp.get("name"),
                        change_type='unchanged',
                        old_version=old_version,
                        new_version=new_version,
                        ecosystem=ecosystem
                    ))
        
        # Find removed components
        for key, old_comp in old_comps.items():
            if key not in new_comps:
                changes['removed'].append(DependencyChange(
                    name=old_comp.get("name"),
                    change_type='removed',
                    old_version=old_comp.get("version", ""),
                    ecosystem=old_comp.get("ecosystem")
                ))
        
        return changes
    
    def _is_upgrade(self, old_version: str, new_version: str) -> bool:
        """
        Determine if version change is an upgrade
        
        Args:
            old_version: Old version string
            new_version: New version string
        
        Returns:
            True if new_version > old_version
        """
        try:
            # Simple semantic version comparison
            old_parts = self._parse_version(old_version)
            new_parts = self._parse_version(new_version)
            
            # Compare version parts
            for old, new in zip(old_parts, new_parts):
                if new > old:
                    return True
                elif new < old:
                    return False
            
            # If all parts equal, longer version is considered newer
            return len(new_parts) > len(old_parts)
        
        except Exception:
            # If parsing fails, use string comparison
            return new_version > old_version
    
    def _parse_version(self, version: str) -> List[int]:
        """
        Parse semantic version string
        
        Args:
            version: Version string (e.g., '1.2.3', 'v2.0.0-beta')
        
        Returns:
            List of version numbers
        """
        # Remove 'v' prefix if present
        version = version.lstrip('v')
        
        # Split on dots and handle pre-release tags
        parts = version.split('-')[0]  # Ignore pre-release tags for now
        
        # Extract numeric parts
        numeric_parts = []
        for part in parts.split('.'):
            try:
                numeric_parts.append(int(part))
            except ValueError:
                # Non-numeric part (e.g., 'beta'), skip
                pass
        
        return numeric_parts
    
    def get_summary(self, changes: Dict[str, List[DependencyChange]]) -> Dict[str, int]:
        """
        Get summary statistics of changes
        
        Args:
            changes: Changes dictionary from compare()
        
        Returns:
            Summary dict with counts
        """
        return {
            'total_changes': len(changes['added']) + len(changes['removed']) + 
                           len(changes['upgraded']) + len(changes['downgraded']),
            'added': len(changes['added']),
            'removed': len(changes['removed']),
            'upgraded': len(changes['upgraded']),
            'downgraded': len(changes['downgraded']),
            'unchanged': len(changes['unchanged'])
        }
    
    def format_markdown(self, changes: Dict[str, List[DependencyChange]]) -> str:
        """
        Format changes as markdown
        
        Args:
            changes: Changes dictionary from compare()
        
        Returns:
            Markdown-formatted string
        """
        lines = []
        summary = self.get_summary(changes)
        
        lines.append("## 📊 Dependency Changes\n")
        lines.append(f"**Summary:** {summary['total_changes']} change(s) detected\n")
        lines.append(f"- 🟢 Added: {summary['added']}\n")
        lines.append(f"- 🔴 Removed: {summary['removed']}\n")
        lines.append(f"- 🔵 Upgraded: {summary['upgraded']}\n")
        lines.append(f"- 🟡 Downgraded: {summary['downgraded']}\n")
        
        # Show details if there are changes
        if summary['total_changes'] > 0:
            lines.append("\n### Details\n")
            
            if changes['added']:
                lines.append("\n**Added Dependencies:**\n")
                for change in changes['added']:
                    lines.append(f"- `{change.name}@{change.new_version}`\n")
            
            if changes['removed']:
                lines.append("\n**Removed Dependencies:**\n")
                for change in changes['removed']:
                    lines.append(f"- `{change.name}@{change.old_version}`\n")
            
            if changes['upgraded']:
                lines.append("\n**Upgraded Dependencies:**\n")
                for change in changes['upgraded']:
                    lines.append(f"- `{change.name}`: {change.old_version} → {change.new_version}\n")
            
            if changes['downgraded']:
                lines.append("\n**Downgraded Dependencies:**\n")
                for change in changes['downgraded']:
                    lines.append(f"- `{change.name}`: {change.old_version} → {change.new_version}\n")
        else:
            lines.append("\n*No dependency changes detected.*\n")
        
        return ''.join(lines)
