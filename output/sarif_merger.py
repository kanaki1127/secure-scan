import hashlib
import json
import os


def compute_fingerprint(result: dict) -> str:
    """SHA-256 hex digest of: ruleId + '|' + artifactLocation.uri of first
    location + '|' + str(startLine of first location region).
    Use empty string for any missing field."""
    rule_id = result.get("ruleId") or ""

    uri = ""
    start_line = ""

    locations = result.get("locations")
    if isinstance(locations, list) and len(locations) > 0:
        first_loc = locations[0]
        if isinstance(first_loc, dict):
            phys_loc = first_loc.get("physicalLocation")
            if isinstance(phys_loc, dict):
                art_loc = phys_loc.get("artifactLocation")
                if isinstance(art_loc, dict):
                    uri = art_loc.get("uri") or ""
                region = phys_loc.get("region")
                if isinstance(region, dict):
                    line_val = region.get("startLine")
                    if line_val is not None:
                        start_line = str(line_val)

    content = f"{rule_id}|{uri}|{start_line}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def merge_sarif(sarif_docs: list[dict]) -> dict:
    """Return a single SARIF 2.1.0 dict with:
       version: "2.1.0"
       $schema: "https://json.schemastore.org/sarif-2.1.0.json"
       runs: [{ tool: { driver: { name: "secure-scan" } }, results: [...] }]
    Concatenate all input results, deduplicate by compute_fingerprint,
    and set result["partialFingerprints"] = {"secureScan/v1": <fp>} on each."""
    all_results = []
    seen_fingerprints = set()

    for doc in sarif_docs:
        runs = doc.get("runs") or []
        for run in runs:
            results = run.get("results") or []
            for res in results:
                fp = compute_fingerprint(res)
                if fp not in seen_fingerprints:
                    seen_fingerprints.add(fp)
                    res["partialFingerprints"] = {"secureScan/v1": fp}
                    all_results.append(res)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secure-scan"
                    }
                },
                "results": all_results
            }
        ]
    }


def load_sarif(path: str) -> dict:
    """Read JSON from disk. Return dict. Raise FileNotFoundError if missing."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_sarif(sarif: dict, path: str) -> None:
    """Write JSON to disk with indent=2."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
