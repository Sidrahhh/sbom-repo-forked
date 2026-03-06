"""
Configuration Loader for PRISM
Centralizes all configuration values that were previously hardcoded
Loads environment variables from .env file
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load .env from project root
    env_path = Path(__file__).parent.parent / '.env'
    load_dotenv(dotenv_path=env_path)
except ImportError:
    # python-dotenv not installed - will use system environment variables only
    pass


class PRISMConfig:
    """Singleton configuration loader"""

    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PRISMConfig, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._config is None:
            self.load_config()

    def load_config(self, config_path: Optional[str] = None):
        """Load configuration from YAML file"""
        if config_path is None:
            # Default to config/prism_config.yaml relative to project root
            script_dir = Path(__file__).parent.parent
            config_path = script_dir / "config" / "prism_config.yaml"

        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, 'r') as f:
            self._config = yaml.safe_load(f)

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation path
        Example: get('risk_scoring.formula.weights.cvss_score')
        """
        keys = key_path.split('.')
        value = self._config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    # Risk Scoring Getters
    def get_risk_weights(self) -> Dict[str, float]:
        """Get risk formula weights"""
        return self.get('risk_scoring.formula.weights', {
            'vulnerability_count': 0.4,
            'cvss_score': 0.5,
            'reachability': 0.1
        })

    def get_max_vuln_count_factor(self) -> float:
        return self.get('risk_scoring.formula.max_vuln_count_factor', 10.0)

    def get_vuln_count_multiplier(self) -> float:
        return self.get('risk_scoring.formula.vuln_count_multiplier', 2.0)

    def get_default_reachability_score(self) -> float:
        return self.get('risk_scoring.formula.default_reachability_score', 0.5)

    def get_cvss_thresholds(self) -> Dict[str, float]:
        """Get CVSS severity thresholds"""
        return {
            'critical': self.get('risk_scoring.cvss_severity.critical.threshold', 9.0),
            'high': self.get('risk_scoring.cvss_severity.high.threshold', 7.0),
            'medium': self.get('risk_scoring.cvss_severity.medium.threshold', 4.0),
            'low': self.get('risk_scoring.cvss_severity.low.threshold', 0.1)
        }

    def get_cvss_numeric_values(self) -> Dict[str, float]:
        """Get numeric CVSS values for severity levels"""
        return {
            'CRITICAL': self.get('risk_scoring.cvss_severity.critical.numeric_value', 9.5),
            'HIGH': self.get('risk_scoring.cvss_severity.high.numeric_value', 7.5),
            'MEDIUM': self.get('risk_scoring.cvss_severity.medium.numeric_value', 5.0),
            'MODERATE': self.get('risk_scoring.cvss_severity.medium.numeric_value', 5.0),
            'LOW': self.get('risk_scoring.cvss_severity.low.numeric_value', 2.5),
            'UNKNOWN': self.get('risk_scoring.cvss_severity.unknown.numeric_value', 0.0)
        }

    # Vulnerability Sources Getters
    def get_default_sources(self) -> list:
        return self.get('vulnerability_sources.default_sources', ['osv', 'github', 'kev'])

    def get_api_endpoint(self, source: str) -> Optional[str]:
        """Get API endpoint for a vulnerability source"""
        return self.get(f'vulnerability_sources.endpoints.{source}')

    def get_rate_limit(self, source: str) -> Dict[str, Any]:
        """Get rate limit configuration for a source"""
        return self.get(f'vulnerability_sources.rate_limits.{source}', {
            'delay_seconds': 0,
            'enabled': False
        })

    # Reachability Getters
    def is_level_1_reachability_enabled(self) -> bool:
        return self.get('reachability.level_1.enabled', True)

    def is_level_2_reachability_enabled(self) -> bool:
        return self.get('reachability.level_2.enabled', False)

    def get_scope_weights(self) -> Dict[str, float]:
        return self.get('reachability.level_1.scope_weights', {
            'required': 1.0,
            'optional': 0.5,
            'excluded': 0.0
        })

    def get_dev_dependency_weight(self) -> float:
        return self.get('reachability.level_1.dev_dependency_weight', 0.0)

    def get_import_graph_config(self) -> Dict[str, Any]:
        return self.get('reachability.level_2.import_graph', {
            'enabled': True,
            'max_depth': 10
        })

    def get_call_graph_config(self) -> Dict[str, Any]:
        return self.get('reachability.level_2.call_graph', {
            'enabled': True,
            'supported_languages': ['javascript', 'python', 'typescript'],
            'confidence': {
                'direct_call': 1.0,
                'indirect_call': 0.8,
                'conditional_call': 0.6,
                'unused_import': 0.2
            }
        })

    # Policy Engine Getters
    def is_opa_enabled(self) -> bool:
        return self.get('policy_engine.opa.enabled', False)

    def get_opa_server_url(self) -> str:
        return self.get('policy_engine.opa.server_url', 'http://localhost:8181')

    def get_opa_policy_path(self) -> str:
        return self.get('policy_engine.opa.policy_path', '/v1/data/prism/allow')

    def get_opa_timeout(self) -> int:
        return self.get('policy_engine.opa.timeout_seconds', 5)

    def should_fallback_to_python_policy(self) -> bool:
        return self.get('policy_engine.opa.fallback_to_python', True)

    def get_python_rules_file(self) -> str:
        return self.get('policy_engine.python.rules_file', 'rules/blocked_packages.yaml')

    # Remediation Getters
    def get_priority_thresholds(self) -> Dict[str, float]:
        return {
            'critical': self.get('remediation.priority.critical', 9.0),
            'high': self.get('remediation.priority.high', 7.0),
            'medium': self.get('remediation.priority.medium', 4.0),
            'low': self.get('remediation.priority.low', 0.1)
        }

    def get_package_manager_command(self, ecosystem: str) -> str:
        return self.get(f'remediation.package_managers.{ecosystem}', f'{ecosystem} install')

    # AI Configuration Getters
    def is_ai_enabled(self) -> bool:
        return self.get('ai.enabled', False)

    def get_openai_config(self) -> Dict[str, Any]:
        """Get OpenAI configuration with API key from environment"""
        config = {
            'model': self.get('ai.openai.model', 'gpt-4'),
            'temperature': self.get('ai.openai.temperature', 0.3),
            'max_tokens': self.get('ai.openai.max_tokens', 2000),
            'timeout_seconds': self.get('ai.openai.timeout_seconds', 30)
        }

        # Get API key from environment variable
        api_key_env = self.get('ai.openai.api_key_env', 'OPENAI_API_KEY')
        api_key = os.getenv(api_key_env)
        if api_key:
            config['api_key'] = api_key

        return config

    def get_ai_features(self) -> Dict[str, bool]:
        return self.get('ai.features', {
            'context_aware_remediation': True,
            'changelog_analysis': True,
            'breaking_change_prediction': True,
            'natural_language_explanations': True,
            'code_analysis': True,
            'learning_from_feedback': False
        })

    def get_code_context_config(self) -> Dict[str, Any]:
        return self.get('ai.code_context', {
            'max_files_to_analyze': 50,
            'file_size_limit_kb': 500,
            'include_patterns': ['**/*.js', '**/*.ts', '**/*.py'],
            'exclude_patterns': ['**/node_modules/**', '**/dist/**']
        })

    # Multi-Agent System Getters
    def is_multi_agent_enabled(self) -> bool:
        return self.get('multi_agent.enabled', False)

    def get_enabled_agents(self) -> list:
        """Get list of enabled agent names"""
        agents_config = self.get('multi_agent.agents', {})
        return [
            agent_name
            for agent_name, config in agents_config.items()
            if config.get('enabled', False)
        ]

    def get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        return self.get(f'multi_agent.agents.{agent_name}', {})

    # Reporting Getters
    def get_output_directory(self) -> str:
        return self.get('reporting.output_directory', 'output')

    def get_report_formats(self) -> list:
        return self.get('reporting.formats', ['markdown', 'json'])

    def get_markdown_config(self) -> Dict[str, bool]:
        return self.get('reporting.markdown', {
            'include_emojis': True,
            'include_remediation': True,
            'include_kev_warnings': True,
            'include_reachability_details': True,
            'include_ai_insights': True
        })


# Global singleton instance
config = PRISMConfig()


# Convenience function
def get_config() -> PRISMConfig:
    """Get global configuration instance"""
    return config


if __name__ == "__main__":
    # Test configuration loading
    cfg = get_config()

    print("=== PRISM Configuration Test ===\n")

    print("Risk Weights:", cfg.get_risk_weights())
    print("CVSS Thresholds:", cfg.get_cvss_thresholds())
    print("Default Sources:", cfg.get_default_sources())
    print("OSV Endpoint:", cfg.get_api_endpoint('osv'))
    print("OPA Enabled:", cfg.is_opa_enabled())
    print("AI Enabled:", cfg.is_ai_enabled())
    print("Multi-Agent Enabled:", cfg.is_multi_agent_enabled())
    print("\n✅ Configuration loaded successfully!")
