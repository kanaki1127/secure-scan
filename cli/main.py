import argparse
import sys

from config.loader import load_config
from analyzers.dispatcher import scan_target
from output.sarif_merger import save_sarif, load_sarif
from output.enricher import enrich_sarif
from output.baseline import diff_baseline
from output.console_formatter import format_console


def _severity_of(result: dict) -> str:
    props = result.get("properties", {})
    if props.get("severity"):
        return str(props["severity"]).lower()
    level = result.get("level")
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "low")


def _counts(results: list) -> dict:
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        s = _severity_of(r)
        if s in c:
            c[s] += 1
    return c


def main() -> None:
    parser = argparse.ArgumentParser(prog="secure-scan")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("target")
    p_scan.add_argument("--format", choices=["sarif", "console", "json"], default="sarif")
    p_scan.add_argument("--output", default="report.sarif")
    p_scan.add_argument("--baseline", default=None)
    p_scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None)
    p_scan.add_argument("--config", default="secure-scan.yml")

    p_base = sub.add_parser("baseline-save")
    p_base.add_argument("target")
    p_base.add_argument("--output", required=True)
    p_base.add_argument("--config", default="secure-scan.yml")

    p_serve = sub.add_parser("serve")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()

    if args.command == "scan":
        cfg = load_config(args.config)
        sarif = scan_target(args.target, cfg)
        if args.baseline:
            sarif = diff_baseline(sarif, load_sarif(args.baseline))
        sarif = enrich_sarif(sarif)
        if args.format == "console":
            print(format_console(sarif))
        else:
            save_sarif(sarif, args.output)
        results = sarif.get("runs", [{}])[0].get("results", [])
        c = _counts(results)
        print(f"secure-scan: {len(results)} findings "
              f"({c['critical']} critical, {c['high']} high, "
              f"{c['medium']} medium, {c['low']} low)")
        if args.fail_on:
            order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            threshold = order[args.fail_on]
            for r in results:
                if order.get(_severity_of(r), 0) >= threshold:
                    sys.exit(1)

    elif args.command == "baseline-save":
        cfg = load_config(args.config)
        sarif = enrich_sarif(scan_target(args.target, cfg))
        save_sarif(sarif, args.output)
        print(f"Baseline saved to {args.output}")

    elif args.command == "serve":
        import uvicorn
        from web.app import app
        uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()