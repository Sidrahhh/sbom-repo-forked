from agent.config_loader import get_config


def cvss_to_severity(score: float, thresholds: dict = None) -> str:
    """
    Convert CVSS score to severity level.

    Args:
        score: CVSS score (0.0 - 10.0)
        thresholds: Optional dict with custom thresholds
                   e.g., {"critical": 9.0, "high": 7.0, "medium": 4.0}

    Returns:
        Severity string: CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN
    """
    if score is None or score == 0.0:
        return "UNKNOWN"

    # Use custom thresholds if provided, otherwise load from config
    if thresholds is None:
        cfg = get_config()
        thresholds = cfg.get_cvss_thresholds()

    if score >= thresholds.get("critical", 9.0):
        return "CRITICAL"
    elif score >= thresholds.get("high", 7.0):
        return "HIGH"
    elif score >= thresholds.get("medium", 4.0):
        return "MEDIUM"
    else:
        return "LOW"