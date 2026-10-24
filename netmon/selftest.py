"""Self-test: proof that the monitor still works.

Security tools fail silently - a setting raised too far, a blocklist that stopped loading, or a capture that
stopped receiving packets all look exactly like "no attacks". The self-test catches that:

1. Detection drills. Textbook versions of common attacks (an nmap-style scan of 1,000 ports, a password-guessing
   run, a 20 MB upload, a malware beacon...) are replayed as packet records into a *separate* sandbox analyser
   that uses your current settings and blocklists. Nothing is sent on the network and nothing reaches your
   alert list or notifications. If a drill is not detected, your settings would miss that attack too.
2. Capture health (live mode): packets must keep arriving. A capture that has gone quiet is reported.

For an end-to-end test with real packets on your own computer, run labs/self_lab.py and the benchmark.
In live mode the self-test runs at start and every 6 hours; a failed drill raises a "Self-test" alert.
"""

from __future__ import annotations

import copy
import time

from .analyzer import Analyzer, Config, PacketInfo
from .payload import build_client_hello, parse_client_hello

ATTACKER, VICTIM, ROUTER, OUTSIDE = "10.254.0.66", "10.254.0.10", "10.254.0.1", "198.51.100.250"
T0 = 1_700_000_000.0


def _scan():
    return [PacketInfo(T0 + port * 0.01, ATTACKER, VICTIM, "TCP", 60, 50000, port, "S") for port in range(1, 1001)]


def _syn_flood():
    return [PacketInfo(T0 + i * 0.001, f"203.0.113.{i % 200 + 1}", VICTIM, "TCP", 60, 1024 + i, 80, "S")
            for i in range(2000)]


def _brute_force():
    return [PacketInfo(T0 + i * 0.9, ATTACKER, VICTIM, "TCP", 60, 40000 + i, 22, "S") for i in range(64)]


def _upload():
    return [PacketInfo(T0 + i * 0.0007, VICTIM, OUTSIDE, "TCP", 1500, 51000, 443, "A") for i in range(14000)]


def _dns_tunnel():
    label = "a3f9c1e07b5d2846f1e9c0b7a5d3e1f2c4b6a8d0e2f4a6c8e0b2d4f6a8c0e2b4"[:60]
    return [PacketInfo(T0 + i, VICTIM, ROUTER, "DNS", 120, 50000 + i, 53, dns_query=f"{label}{i}.t.example.")
            for i in range(5)]


def _beacon():
    out = []
    for i in range(14):
        t = T0 + i * 60 + (1.5 if i % 2 else -1.5)
        out.append(PacketInfo(t, VICTIM, OUTSIDE, "TCP", 60, 45000 + i, 443, "S"))
    return out


def _arp():
    return [PacketInfo(T0, ROUTER, VICTIM, "ARP", 42, src_mac="02:00:00:00:00:01"),
            PacketInfo(T0 + 5, ROUTER, VICTIM, "ARP", 42, src_mac="02:00:00:00:00:66")]


def _risky():
    return [PacketInfo(T0, ATTACKER, ROUTER, "TCP", 60, 61001, 23, "S")]


def _tls():
    normal = parse_client_hello(build_client_hello("www.example.com"))["ja4"]
    odd = parse_client_hello(build_client_hello(None, ciphers=[0xC02F, 0x002F], extensions=[0x000A, 0x000D],
                                                alpn=()))["ja4"]
    out = [PacketInfo(T0 + i * 20, VICTIM, OUTSIDE, "TCP", 600, 40000 + i, 443, "PA", tls_sni="www.example.com",
                      ja4=normal) for i in range(30)]
    return out + [PacketInfo(T0 + 650, VICTIM, "198.51.100.251", "TCP", 300, 47000, 443, "PA", ja4=odd)]


# name, what it imitates, detector expected, packet generator
DRILLS = [
    ("Port scan", "nmap-style scan of 1,000 ports in 10 seconds", "Port scan", _scan),
    ("SYN flood", "2,000 connection attempts per second (denial of service)", "SYN flood", _syn_flood),
    ("Password guessing", "64 SSH login attempts in one minute (e.g. Hydra)", "Brute force", _brute_force),
    ("Data theft", "20 MB uploaded to an outside server in 10 seconds", "High traffic", _upload),
    ("DNS tunnelling", "data hidden in 60-character DNS names (e.g. iodine)", "Suspicious DNS", _dns_tunnel),
    ("Malware beacon", "calling home every 60 seconds for 14 minutes", "Beaconing", _beacon),
    ("ARP spoofing", "a second device claiming the router's address", "ARP spoofing", _arp),
    ("Telnet attempt", "unencrypted remote login to the router", "Risky port", _risky),
    ("Unknown encrypted program", "a new program connects without naming a website", "Unusual TLS client", _tls),
]


def _intel_drill(intel):
    """A connection to the first address on a loaded blocklist (only when lists are loaded)."""
    ip = next(iter(intel.ips), None) if intel is not None else None
    if not ip:
        return None
    return ("Blocklisted server", f"connection to {ip} from your blocklists", "Threat intel",
            lambda: [PacketInfo(T0, VICTIM, ip, "TCP", 60, 40000, 443, "S")])


def run_drills(config: Config | None = None, intel=None) -> dict:
    """Run every drill in a sandbox analyser with a copy of the given settings. Returns a report."""
    drills = list(DRILLS)
    extra = _intel_drill(intel)
    if extra:
        drills.append(extra)
    results = []
    for name, imitates, expected, make in drills:
        sandbox = Analyzer(copy.deepcopy(config) if config else Config(), intel=intel)
        packets = make()
        caught = None
        for p in packets:
            for alert in sandbox.process(p):
                if alert.kind == expected and caught is None:
                    caught = alert.ts - packets[0].ts
        results.append({"drill": name, "imitates": imitates, "detector": expected, "ok": caught is not None,
                        "seconds_to_detect": round(caught, 1) if caught is not None else None,
                        "fix": None if caught is not None else _fix(expected)})
    passed = sum(r["ok"] for r in results)
    return {"ts": time.time(), "passed": passed, "total": len(results), "ok": passed == len(results),
            "results": results}


def _fix(kind: str) -> str:
    settings = {"Port scan": "port_scan_ports / port_scan_window", "SYN flood": "syn_flood_count",
                "Brute force": "brute_force_attempts / brute_force_window", "High traffic": "heavy_bytes",
                "Suspicious DNS": "dns_label_length / dns_entropy", "Beaconing": "beacon_min_connections / "
                "beacon_max_jitter", "Unusual TLS client": "tls_learn_seconds"}
    if kind in settings:
        return f"Your current settings would miss this attack - check {settings[kind]} in Settings."
    return "This detector did not fire - please report it as a bug."


def capture_health(analyzer: Analyzer, live: bool, now: float | None = None, quiet_after: float = 120) -> dict:
    """Is traffic still arriving? Only meaningful for live capture."""
    if not live:
        return {"state": "not live", "detail": "Reading a file - capture health applies to live monitoring."}
    now = now or time.time()
    if analyzer.last_ts is None:
        return {"state": "waiting", "detail": "No packets yet. If this lasts, check the interface name and sudo."}
    quiet = now - analyzer.last_ts
    if quiet > quiet_after:
        return {"state": "stalled", "detail": f"No packets for {quiet / 60:.0f} minutes - the capture may have "
                                               "stopped or the computer lost its network."}
    return {"state": "ok", "detail": f"Last packet {quiet:.0f} s ago, {analyzer.packets:,} packets so far."}
