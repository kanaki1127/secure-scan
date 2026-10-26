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


def _get_location_info(result: dict) -> tuple[str, str]:
    locations = result.get("locations")
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, dict):
            phys = first.get("physicalLocation")
            if isinstance(phys, dict):
                artifact = phys.get("artifactLocation")
                region = phys.get("region")
                uri = "-"
                if isinstance(artifact, dict) and artifact.get("uri") is not None:
                    uri = str(artifact.get("uri"))
                line = "-"
                if isinstance(region, dict) and region.get("startLine") is not None:
                    line = str(region.get("startLine"))
                return uri, line
    return "-", "-"


def format_pr_comment(sarif: dict, max_rows: int = 20) -> str:
    """Returns GitHub-flavored Markdown.

    If there are zero findings, return exactly:
        "## 🔒 secure-scan: no findings 🎉"

    Otherwise:
        Start with "## 🔒 secure-scan findings\n\n"
        Then a Markdown table with columns:
            Severity | File | Line | Rule | CWE | Fix
        One row per finding, sorted by severity: critical > high > medium > low.
        If total findings > max_rows, append:
            "\n_…and N more findings. See the full SARIF report._"
    """
    results = []
    runs = sarif.get("runs", [])
    if isinstance(runs, list) and runs:
        res = runs[0].get("results", [])
        if isinstance(res, list):
            results = res

    findings = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for r in results:
        if not isinstance(r, dict):
            continue
        sev = _get_severity(r)
        file_path, line = _get_location_info(r)
        rule_id = str(r.get("ruleId", "") or "-")

        props = r.get("properties")
        cwe = "-"
        fix = "-"
        if isinstance(props, dict):
            if props.get("cwe"):
                cwe = str(props["cwe"])
            if props.get("remediation"):
                fix = str(props["remediation"])

        findings.append({
            "severity": sev,
            "file": file_path,
            "line": line,
            "rule": rule_id,
            "cwe": cwe,
            "fix": fix,
            "rank": severity_order.get(sev, 4),
        })

    if not findings:
        return "## 🔒 secure-scan: no findings 🎉"

    findings.sort(key=lambda x: x["rank"])

    table_lines = [
        "## 🔒 secure-scan findings\n",
        "| Severity | File | Line | Rule | CWE | Fix |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    displayed = findings[:max_rows]
    for f in displayed:
        table_lines.append(
            f"| {f['severity']} | {f['file']} | {f['line']} | {f['rule']} | {f['cwe']} | {f['fix']} |"
        )

    output = "\n".join(table_lines)

    if len(findings) > max_rows:
        remaining = len(findings) - max_rows
        output += f"\n\n_…and {remaining} more findings. See the full SARIF report._"

    return output
