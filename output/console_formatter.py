def _get_severity(result: dict) -> str:
    props = result.get("properties")
    if isinstance(props, dict) and "severity" in props and props["severity"] is not None:
        return str(props["severity"]).lower()

    level = result.get("level")
    if level == "error":
        return "high"
    elif level == "warning":
        return "medium"
    elif level == "note":
        return "low"
    return "low"


def _get_location_info(result: dict) -> tuple[str, int]:
    locations = result.get("locations")
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, dict):
            phys = first.get("physicalLocation")
            if isinstance(phys, dict):
                artifact = phys.get("artifactLocation")
                region = phys.get("region")
                uri = ""
                if isinstance(artifact, dict):
                    uri = artifact.get("uri", "") or ""
                line = 0
                if isinstance(region, dict):
                    line = region.get("startLine", 0) or 0
                return str(uri), int(line)
    return "", 0


def format_console(sarif: dict) -> str:
    """Returns a plain-text report using this exact layout:

    === secure-scan report ===
    Total findings: <N>
    Critical: <n>  High: <n>  Medium: <n>  Low: <n>

    <file_path>:<line>
      [<SEVERITY>] <ruleId>
      <message text>
      Fix: <remediation if present else "See CWE page">

    ...one block per finding, grouped by file path and sorted by line number.
    """
    results = []
    runs = sarif.get("runs", [])
    if isinstance(runs, list) and runs:
        res = runs[0].get("results", [])
        if isinstance(res, list):
            results = res

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings = []

    for r in results:
        if not isinstance(r, dict):
            continue
        sev = _get_severity(r)
        if sev in counts:
            counts[sev] += 1
        else:
            counts["low"] += 1

        file_path, line = _get_location_info(r)
        rule_id = r.get("ruleId", "") or ""

        msg_obj = r.get("message")
        msg_text = ""
        if isinstance(msg_obj, dict):
            msg_text = msg_obj.get("text", "") or ""
        elif isinstance(msg_obj, str):
            msg_text = msg_obj

        props = r.get("properties")
        remediation = None
        if isinstance(props, dict):
            remediation = props.get("remediation")

        findings.append({
            "file": file_path,
            "line": line,
            "severity": sev.upper(),
            "rule_id": rule_id,
            "message": msg_text,
            "remediation": remediation if remediation else "See CWE page",
        })

    lines = [
        "=== secure-scan report ===",
        f"Total findings: {len(findings)}",
        f"Critical: {counts['critical']}  High: {counts['high']}  Medium: {counts['medium']}  Low: {counts['low']}",
    ]

    if not findings:
        return "\n".join(lines)

    # Group by file path and sort by line number
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)

    for file_path in sorted(by_file.keys()):
        file_findings = sorted(by_file[file_path], key=lambda x: x["line"])
        for item in file_findings:
            lines.append("")
            lines.append(f"{item['file']}:{item['line']}")
            lines.append(f"  [{item['severity']}] {item['rule_id']}")
            lines.append(f"  {item['message']}")
            lines.append(f"  Fix: {item['remediation']}")

    return "\n".join(lines)
