from analyzers.semgrep_runner import run_semgrep_sarif
from config.loader import Config


def scan_target(target_path: str, config: Config) -> dict:
    """rules = config.enabled_rules[0] if config.enabled_rules else 'auto'
    Return run_semgrep_sarif(target_path, rules=rules)."""
    rules = config.enabled_rules[0] if config.enabled_rules else "auto"
    return run_semgrep_sarif(target_path, rules=rules)
