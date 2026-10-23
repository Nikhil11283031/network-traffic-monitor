"""Command line entry point.

    sudo python3 -m netmon live                     watch your network, dashboard on http://127.0.0.1:5050
    sudo python3 -m netmon live --iface en0         pick the interface (en0 is usually Wi-Fi on a Mac)
    python3 -m netmon pcap samples/demo.pcap        analyse a saved capture (no sudo needed)
    python3 -m netmon pcap samples/demo.pcap --speed 5   replay it live on the dashboard
    python3 -m netmon pcap samples/demo.pcap --no-web --report report.json
    python3 -m netmon pcap samples/demo.pcap --no-web --investigate    AI analyst writes an incident report
    python3 -m netmon update-intel                  download free threat-intelligence blocklists into intel/

The AI analyst uses Claude when ANTHROPIC_API_KEY is set, otherwise a free local model through Ollama if it is
running, otherwise a built-in rule-based analyst.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime

from .analyzer import Analyzer
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


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netmon", description="Network traffic monitor with threat alerts.")
    sub = parser.add_subparsers(dest="mode", required=True)
    live = sub.add_parser("live", help="watch a network interface (needs sudo)")
    live.add_argument("--iface", help="interface name, e.g. en0 (default: the system's main one)")
    live.add_argument("--filter", help='optional capture filter, e.g. "tcp or udp port 53"')
    pcap = sub.add_parser("pcap", help="analyse a saved .pcap file")
    pcap.add_argument("path")
    pcap.add_argument("--speed", type=float, default=0, help="replay speed for the dashboard (0 = instant)")
    intel_cmd = sub.add_parser("update-intel", help="download free threat-intelligence blocklists")
    intel_cmd.add_argument("--dir", default="intel", help="folder to save the lists in (default intel/)")
    for p in (live, pcap):
        p.add_argument("--host", default="127.0.0.1",
                       help="dashboard address (default 127.0.0.1 = this computer only; Docker uses 0.0.0.0)")
        p.add_argument("--intel", default="intel", help="folder of threat-intelligence lists (default intel/)")
        p.add_argument("--no-intel", action="store_true", help="do not check threat-intelligence lists")
        p.add_argument("--no-ml", action="store_true", help="turn off machine-learning anomaly detection")
        p.add_argument("--ml-learn", type=float, default=None,
                       help="seconds of traffic the ML model learns from (default 40 for files, 300 for live)")
        p.add_argument("--no-web", action="store_true", help="console output only, no dashboard")
        p.add_argument("--port", type=int, default=5050, help="dashboard port (default 5050)")
        p.add_argument("--report", help="save a JSON report to this file when finished")
        p.add_argument("--investigate", action="store_true",
                       help="when finished, have the AI analyst write an incident report (with --no-web)")
    args = parser.parse_args(argv)

    if args.mode == "update-intel":
        from .threatintel import update_feeds

        print(f"Downloading threat-intelligence feeds into {args.dir}/ ...")
        for line in update_feeds(args.dir):
            print("  " + line)
        return 0

    intel = None
    if not args.no_intel:
        from .threatintel import ThreatIntel

        intel = ThreatIntel().load_dir(args.intel)
        print(f"Threat intelligence: {intel.size:,} indicators from {len(intel.lists)} list(s) in {args.intel}/"
              + ("" if intel.size else " (run: python3 -m netmon update-intel)"))
    ml = None
    if not args.no_ml:
        from .ml import AnomalyDetector

        learn = args.ml_learn if args.ml_learn is not None else (300 if args.mode == "live" else 40)
        ml = AnomalyDetector(learn_seconds=learn)
        print("Machine learning: " + (f"Isolation Forest, learning normal behaviour for the first {learn:g} s"
                                      if not ml.error else ml.error))
    analyzer = Analyzer(intel=intel, ml=ml)
    if args.mode == "live":
        source = f"live: {args.iface or 'default interface'}"
        worker = lambda: live_capture(analyzer, args.iface, args.filter, on_alert=print_alert)  # noqa: E731
    else:
        source = f"file: {args.path}"
        worker = lambda: read_pcap(analyzer, args.path, args.speed, on_alert=print_alert)  # noqa: E731

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
            create_app(analyzer, source).run(host=args.host, port=args.port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Live capture needs administrator rights. Run it with sudo, e.g. sudo python3 -m netmon live")
        return 1
    finally:
        time.sleep(0.1)
        snapshot = analyzer.snapshot()
        print_summary(snapshot)
        if args.investigate:
            from .agent import SecurityAnalystAgent

            agent = SecurityAnalystAgent(analyzer)
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
