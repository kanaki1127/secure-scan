import re
from compliance.mapping import lookup


def enrich_sarif(sarif: dict) -> dict:
    """Iterate over sarif["runs"][0]["results"].
    For each result:
      1. Try result.get("properties", {}).get("cwe") for the CWE id.
      2. If absent, apply regex CWE-(\\d+) to result.get("ruleId","")
         and use "CWE-<number>" if it matches.
      3. If a CWE id is found, call lookup(). If it returns a dict, ensure
         result has a "properties" dict (create if missing) and set:
           properties["cwe"]         = cwe_id
           properties["cwe_name"]    = entry["name"]
           properties["owasp"]       = entry["owasp"]
           properties["pci_dss"]     = entry["pci_dss"]
           properties["remediation"] = entry["remediation"]
      4. If no CWE found or lookup returns None, leave the result unchanged.
    Returns the same sarif dict. Never raise."""
    try:
        runs = sarif.get("runs")
        if not runs or not isinstance(runs, list):
            return sarif
        results = runs[0].get("results")
        if not results or not isinstance(results, list):
            return sarif

        for result in results:
            if not isinstance(result, dict):
                continue

            cwe_id = None
            props = result.get("properties")
            if isinstance(props, dict):
                cwe_id = props.get("cwe")

            if not cwe_id:
                rule_id = result.get("ruleId", "")
                if isinstance(rule_id, str):
                    m = re.search(r"CWE-(\d+)", rule_id)
                    if m:
                        cwe_id = f"CWE-{m.group(1)}"

            if cwe_id:
                entry = lookup(cwe_id)
                if isinstance(entry, dict):
                    if "properties" not in result or not isinstance(result["properties"], dict):
                        result["properties"] = {}
                    result["properties"]["cwe"] = cwe_id
                    result["properties"]["cwe_name"] = entry["name"]
                    result["properties"]["owasp"] = entry["owasp"]
                    result["properties"]["pci_dss"] = entry["pci_dss"]
                    result["properties"]["remediation"] = entry["remediation"]
    except Exception:
        pass

    return sarif
