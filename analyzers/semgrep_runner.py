import json
import subprocess


def run_semgrep_json(target_path: str, rules: str = "auto") -> dict:
    """Run: semgrep scan --config {rules} --json {target_path}
    via subprocess.run(capture_output=True, text=True, check=False).
    Parse stdout as JSON and return as dict.
    If stdout is not valid JSON, raise RuntimeError with stderr in the message.
    Pass arguments as a list. Never use shell=True."""
    cmd = ["semgrep", "scan", "--config", rules, "--json", target_path]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    try:
        return json.loads(result.stdout)
    except Exception as e:
        raise RuntimeError(f"Failed to parse Semgrep JSON output: {result.stderr}") from e


def run_semgrep_sarif(target_path: str, rules: str = "auto") -> dict:
    """Same as run_semgrep_json but pass --sarif instead of --json.
    Return parsed SARIF dict."""
    cmd = ["semgrep", "scan", "--config", rules, "--sarif", target_path]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    try:
        return json.loads(result.stdout)
    except Exception as e:
        raise RuntimeError(f"Failed to parse Semgrep SARIF output: {result.stderr}") from e