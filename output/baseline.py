from output.sarif_merger import compute_fingerprint


def diff_baseline(current: dict, baseline: dict) -> dict:
    """Return SARIF with only findings whose fingerprint is NOT in baseline."""
    baseline_fps = set()
    for r in baseline.get("runs", [{}])[0].get("results", []):
        baseline_fps.add(compute_fingerprint(r))

    current_results = current.get("runs", [{}])[0].get("results", [])
    new_results = [r for r in current_results if compute_fingerprint(r) not in baseline_fps]

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "secure-scan"}},
            "results": new_results,
        }],
    }