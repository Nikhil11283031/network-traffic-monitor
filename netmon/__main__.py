"""Command line entry point.

    python3 -m netmon pcap samples/demo.pcap --speed 5      replay the demo on the dashboard (http://127.0.0.1:5050)
    sudo .venv/bin/python -m netmon live --iface en0         watch your own Wi-Fi live
    python3 -m netmon pcap capture.pcap --no-web --investigate --pdf report.pdf
    python3 -m netmon update-intel                           download threat-intelligence blocklists
    python3 -m netmon update-geoip                           download the free country database
    python3 -m netmon history --severity high                show saved alerts from earlier runs
    python3 -m netmon mcp                                    MCP server for Claude Desktop and other AI apps
    python3 -m netmon benchmark Friday.pcap --truth cicids2017-friday   accuracy on a public dataset

Notifications: --notify-mac, --discord-webhook URL, --slack-webhook URL, --webhook URL, --email-to ADDRESS
(email uses NETMON_SMTP_HOST / _PORT / _USER / _PASSWORD / _FROM).

The AI analyst uses Claude when ANTHROPIC_API_KEY is set, otherwise a free local model through Ollama if it is
running, otherwise a built-in rule-based analyst.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime

from .capture import live_capture, read_pcap

COLOURS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[90m"}


def print_alert(alert):
    when = datetime.fromtimestamp(alert.ts).strftime("%H:%M:%S")
    print(f"{COLOURS.get(alert.severity, '')}[{when}] {alert.severity.upper():6} {alert.kind}: "
          f"{alert.message}\033[0m", flush=True)


def print_summary(snapshot):
    print("\n=== Summary ===")
    print(f"Packets: {snapshot['packets']:,}   Data: {snapshot['bytes'] / 1_000_000:.2f} MB   "
          f"Duration: {snapshot['duration']:.0f} s")
    print("Protocols: " + ", ".join(f"{k} {v}" for k, v in snapshot["protocols"].items()))
    print(f"Devices on the local network: {len(snapshot['devices'])}")
    counts = snapshot["alert_counts"]
    print("Alerts: " + (", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low", "info") if s in counts)
                        or "none"))
    if snapshot.get("ml"):
        m = snapshot["ml"]
        print(f"Machine learning: {m['state']}" + (f", trained on {m['trained_on']} samples, scored "
                                                    f"{m['windows_scored']} windows" if m["state"] != "unavailable" else ""))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netmon", description="Network traffic monitor and intrusion detection.")
    sub = parser.add_subparsers(dest="mode", required=True)
    live = sub.add_parser("live", help="watch a network interface (needs sudo)")
    live.add_argument("--iface", help="interface name, e.g. en0 (default: the system's main one)")
    live.add_argument("--filter", help='optional capture filter, e.g. "tcp or udp port 53"')
    pcap = sub.add_parser("pcap", help="analyse a saved .pcap file")
    pcap.add_argument("path")
    pcap.add_argument("--speed", type=float, default=0, help="replay speed for the dashboard (0 = instant)")

    intel_cmd = sub.add_parser("update-intel", help="download free threat-intelligence blocklists")
    intel_cmd.add_argument("--dir", default="intel", help="folder to save the lists in (default intel/)")
    geo_cmd = sub.add_parser("update-geoip", help="download the free DB-IP country database")
    geo_cmd.add_argument("--dir", default="geoip", help="folder to save it in (default geoip/)")
    hist = sub.add_parser("history", help="show alerts saved by earlier runs")
    hist.add_argument("--db", default="netmon.db")
    hist.add_argument("--severity", choices=["high", "medium", "low", "info"])
    hist.add_argument("--kind", help='alert type, e.g. "Port scan"')
    hist.add_argument("--search", help="text to look for in the alert")
    hist.add_argument("--open", action="store_true", help="only alerts not yet marked as handled")
    hist.add_argument("--limit", type=int, default=50)
    bench = sub.add_parser("benchmark", help="measure accuracy on a labelled capture (e.g. CIC-IDS2017)")
    bench.add_argument("path", help="the .pcap/.pcapng capture")
    bench.add_argument("--truth", required=True,
                       help="answer key: cicids2017-monday (no attacks), -tuesday, -wednesday, -thursday, -friday, a .json file or a "
                            "UNSW-NB15 ground-truth .csv")
    bench.add_argument("--utc-offset", type=float, default=None,
                       help="time zone of the answer key in hours (CIC-IDS2017 default: -3)")
    bench.add_argument("--out", default="benchmark-results", help="folder for the report (default benchmark-results/)")
    bench.add_argument("--intel", default="intel")
    bench.add_argument("--no-ml", action="store_true")
    bench.add_argument("--ml-learn", type=float, default=600,
                       help="seconds of traffic the ML model learns from (default 600)")
    mcp = sub.add_parser("mcp", help="run an MCP server (stdio) for Claude Desktop and other AI apps")
    mcp.add_argument("--url", default="http://127.0.0.1:5050", help="address of the running dashboard")

    for p in (live, pcap):
        p.add_argument("--host", default="127.0.0.1",
                       help="dashboard address (default 127.0.0.1 = this computer only; Docker uses 0.0.0.0)")
        p.add_argument("--port", type=int, default=5050, help="dashboard port (default 5050)")
        p.add_argument("--no-web", action="store_true", help="console output only, no dashboard")
        p.add_argument("--intel", default="intel", help="folder of threat-intelligence lists (default intel/)")
        p.add_argument("--no-intel", action="store_true", help="do not check threat-intelligence lists")
        p.add_argument("--geoip", default="geoip", help="folder with the country database (default geoip/)")
        p.add_argument("--watch-countries", default="", help='alert on traffic to these countries, e.g. "KP,IR"')
        p.add_argument("--no-ml", action="store_true", help="turn off machine-learning anomaly detection")
        p.add_argument("--ml-learn", type=float, default=None,
                       help="seconds of traffic the ML model learns from (default 40 for files, 300 for live)")
        p.add_argument("--db", default="netmon.db", help="alert history database (default netmon.db)")
        p.add_argument("--no-db", action="store_true", help="do not save alerts")
        p.add_argument("--notify-mac", action="store_true", help="macOS notification for serious alerts")
        p.add_argument("--discord-webhook", help="send serious alerts to this Discord webhook URL")
        p.add_argument("--slack-webhook", help="send serious alerts to this Slack webhook URL")
        p.add_argument("--webhook", help="POST serious alerts as JSON to this URL")
        p.add_argument("--email-to", help="email serious alerts to this address (needs NETMON_SMTP_* settings)")
        p.add_argument("--notify-min", default="high", choices=["high", "medium", "low"],
                       help="lowest severity to notify about (default high)")
        p.add_argument("--report", help="save a JSON report to this file when finished")
        p.add_argument("--pdf", help="save a PDF incident report to this file when finished")
        p.add_argument("--investigate", action="store_true",
                       help="when finished, have the AI analyst write an incident report")
    return parser


def run_benchmark(args) -> int:
    from pathlib import Path

    from .analyzer import Analyzer
    from .benchmark import load_truth, markdown, run
    from .capture import have_dpkt
    from .threatintel import ThreatIntel

    truth = load_truth(args.truth, args.utc_offset)
    print(f"Answer key: {len(truth)} attack(s) from {args.truth}")
    if not have_dpkt():
        print("Tip: pip install dpkt makes reading large captures about 10 times faster.")
    ml = None
    if not args.no_ml:
        from .ml import AnomalyDetector

        ml = AnomalyDetector(learn_seconds=args.ml_learn)
        ml = None if ml.error else ml
    analyzer = Analyzer(intel=ThreatIntel().load_dir(args.intel), ml=ml)
    started = time.time()
    result = run(args.path, truth, analyzer,
                 progress=lambda n: print(f"  {n:,} packets ({n / max(time.time() - started, 1e-6):,.0f}/s)", flush=True))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(args.path).stem
    title = f"Benchmark: {stem} ({args.truth})"
    (out / f"{stem}.md").write_text(markdown(result, title))
    (out / f"{stem}.json").write_text(json.dumps(result, indent=2, default=str))
    print()
    print(markdown(result, title))
    print(f"Saved {out / (stem + '.md')} and {out / (stem + '.json')}")
    return 0


def run_history(args) -> int:
    from .store import AlertStore

    store = AlertStore(args.db)
    rows = store.history(limit=args.limit, severity=args.severity, kind=args.kind, query=args.search,
                         include_acked=not args.open)
    stats = store.stats()
    print(f"{stats['alerts']:,} alerts from {stats['sessions']} run(s) in {args.db}; "
          f"{stats['open_high']} high-severity alert(s) not yet handled.\n")
    for r in reversed(rows):
        when = datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        handled = f"  [handled: {r['ack_note'] or 'yes'}]" if r["acked"] else ""
        print(f"{COLOURS.get(r['severity'], '')}{when} {r['severity'].upper():6} {r['kind']}: {r['message']}"
              f"\033[0m{handled}")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.mode == "update-intel":
        from .threatintel import update_feeds

        print(f"Downloading threat-intelligence feeds into {args.dir}/ ...")
        for line in update_feeds(args.dir):
            print("  " + line)
        return 0
    if args.mode == "update-geoip":
        from .geoip import update_geoip

        print(f"Downloading the DB-IP country database into {args.dir}/ ...")
        print("  " + update_geoip(args.dir))
        return 0
    if args.mode == "history":
        return run_history(args)
    if args.mode == "benchmark":
        return run_benchmark(args)
    if args.mode == "mcp":
        from .mcp_server import MCPServer

        MCPServer(args.url).serve()
        return 0

    from .analyzer import Config
    from .monitor import Monitor

    config = Config()
    if args.watch_countries:
        config.update({"watch_countries": args.watch_countries})
    intel = geo = store = notifier = None
    if not args.no_intel:
        from .threatintel import ThreatIntel

        intel = ThreatIntel().load_dir(args.intel)
        print(f"Threat intelligence: {intel.size:,} indicators from {len(intel.lists)} list(s) in {args.intel}/"
              + ("" if intel.size else " (run: python3 -m netmon update-intel)"))
    from .geoip import GeoIP

    geo = GeoIP().load_dir(args.geoip)
    print(f"GeoIP: {geo.size:,} country ranges" if geo.size else
          "GeoIP: no country database (optional: python3 -m netmon update-geoip)")
    if not geo.size:
        geo = None
    ml_learn = None
    if not args.no_ml:
        from .ml import AnomalyDetector

        ml_learn = args.ml_learn if args.ml_learn is not None else (300 if args.mode == "live" else 40)
        error = AnomalyDetector().error
        print("Machine learning: " + (f"Isolation Forest, learning normal behaviour for the first {ml_learn:g} s"
                                      if not error else error))
        if error:
            ml_learn = None
    if not args.no_db:
        from .store import AlertStore

        store = AlertStore(args.db)
        print(f"Alert history: saving to {args.db} ({store.stats()['alerts']:,} alerts saved so far)")
    spec = {"mac": args.notify_mac, "discord": args.discord_webhook, "slack": args.slack_webhook,
            "webhook": args.webhook, "email": args.email_to, "min_severity": args.notify_min}
    if any(v for k, v in spec.items() if k != "min_severity"):
        from .notify import build_notifier

        notifier = build_notifier(spec)
        print(f"Notifications: {', '.join(c.name for c in notifier.channels)} for {args.notify_min}+ alerts")

    source = f"live: {args.iface or 'default interface'}" if args.mode == "live" else f"file: {args.path}"
    monitor = Monitor(source, config=config, intel=intel, geo=geo, ml_learn=ml_learn, store=store, notifier=notifier)
    monitor.analyzer.listeners.append(print_alert)
    analyzer = monitor.analyzer
    if args.mode == "live":
        worker = lambda: live_capture(analyzer, args.iface, args.filter)  # noqa: E731
    else:
        worker = lambda: read_pcap(analyzer, args.path, args.speed)  # noqa: E731

    print(f"Network monitor - watching {source}. Only monitor networks you own or have permission to monitor.")

    try:
        if args.no_web:
            worker()
        else:
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            import logging

            from .web import create_app

            logging.getLogger("werkzeug").setLevel(logging.WARNING)  # hide the per-request log lines
            shown = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
            print(f"Dashboard: http://{shown}:{args.port}   (Ctrl+C to stop)")
            create_app(monitor=monitor).run(host=args.host, port=args.port, debug=False, use_reloader=False,
                                            threaded=True)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Live capture needs administrator rights. Run it with sudo, e.g. sudo .venv/bin/python -m netmon live")
        return 1
    finally:
        time.sleep(0.1)
        analyzer = monitor.analyzer  # may be a newer session if a file was uploaded
        snapshot = analyzer.snapshot()
        print_summary(snapshot)
        if args.investigate:
            agent = monitor.agent
            print(f"\n=== AI analyst: {agent.label} ===")
            started = time.time()
            agent.on_progress = lambda text: print(f"  [{time.time() - started:5.0f}s] {text}", flush=True)
            result = agent.investigate()
            if result.steps:
                print("Investigation steps: " + " -> ".join(
                    s["tool"] + (f"({', '.join(map(str, s['input'].values()))})" if s["input"] else "")
                    for s in result.steps))
            if result.note:
                print(f"Note: {result.note}")
            print(f"Finished in {time.time() - started:.0f} seconds.\n")
            print(result.report)
        if args.report:
            with open(args.report, "w") as f:
                json.dump(snapshot, f, indent=2)
            print(f"Report saved to {args.report}")
        if args.pdf:
            from .agent import OfflineAnalyst
            from .report import build_pdf

            last = monitor.agent.last_result
            analysis = ({"report": last.report, "by": monitor.agent.label if last.mode == "ai" else "offline analyst"}
                        if last else {"report": OfflineAnalyst(analyzer).answer("Investigate").report,
                                      "by": "offline analyst"})
            with open(args.pdf, "wb") as f:
                f.write(build_pdf(snapshot, analysis, monitor.responder.propose(analyzer), monitor.source))
            print(f"PDF report saved to {args.pdf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
