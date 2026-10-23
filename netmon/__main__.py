"""Command line entry point.

    sudo python3 -m netmon live                     watch your network, dashboard on http://127.0.0.1:5050
    sudo python3 -m netmon live --iface en0         pick the interface (en0 is usually Wi-Fi on a Mac)
    python3 -m netmon pcap samples/demo.pcap        analyse a saved capture (no sudo needed)
    python3 -m netmon pcap samples/demo.pcap --speed 5   replay it live on the dashboard
    python3 -m netmon pcap samples/demo.pcap --no-web --report report.json
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


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netmon", description="Network traffic monitor with threat alerts.")
    sub = parser.add_subparsers(dest="mode", required=True)
    live = sub.add_parser("live", help="watch a network interface (needs sudo)")
    live.add_argument("--iface", help="interface name, e.g. en0 (default: the system's main one)")
    live.add_argument("--filter", help='optional capture filter, e.g. "tcp or udp port 53"')
    pcap = sub.add_parser("pcap", help="analyse a saved .pcap file")
    pcap.add_argument("path")
    pcap.add_argument("--speed", type=float, default=0, help="replay speed for the dashboard (0 = instant)")
    for p in (live, pcap):
        p.add_argument("--no-web", action="store_true", help="console output only, no dashboard")
        p.add_argument("--port", type=int, default=5050, help="dashboard port (default 5050)")
        p.add_argument("--report", help="save a JSON report to this file when finished")
    args = parser.parse_args(argv)

    analyzer = Analyzer()
    if args.mode == "live":
        source = f"live: {args.iface or 'default interface'}"
        worker = lambda: live_capture(analyzer, args.iface, args.filter, on_alert=print_alert)  # noqa: E731
    else:
        source = f"file: {args.path}"
        worker = lambda: read_pcap(analyzer, args.path, args.speed, on_alert=print_alert)  # noqa: E731

    print(f"NetZero netmon - watching {source}. Only monitor networks you own or have permission to monitor.")

    try:
        if args.no_web:
            worker()
        else:
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            from .web import create_app

            print(f"Dashboard: http://127.0.0.1:{args.port}   (Ctrl+C to stop)")
            create_app(analyzer, source).run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Live capture needs administrator rights. Run it with sudo, e.g. sudo python3 -m netmon live")
        return 1
    finally:
        time.sleep(0.1)
        snapshot = analyzer.snapshot()
        print_summary(snapshot)
        if args.report:
            with open(args.report, "w") as f:
                json.dump(snapshot, f, indent=2)
            print(f"Report saved to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
