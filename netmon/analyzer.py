"""Traffic analysis and detection rules.

The analyser works on simple PacketInfo records, not on raw packets, so it can be tested without capturing
anything and works the same for live traffic and saved .pcap files. All time windows use the packets' own
timestamps, so replaying a capture file gives the same alerts as watching it live.
"""

from __future__ import annotations

import ipaddress
import math
import threading
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field

# Ports that are commonly abused or should not normally be used on a home or office network.
RISKY_PORTS = {
    21: "FTP (unencrypted file transfer)",
    23: "Telnet (unencrypted remote login)",
    445: "SMB file sharing",
    1433: "Microsoft SQL Server",
    3389: "Remote Desktop (RDP)",
    4444: "Common backdoor / Metasploit port",
    5900: "VNC remote desktop",
    6667: "IRC (often used by botnets)",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class PacketInfo:
    ts: float  # seconds since the epoch
    src: str
    dst: str
    proto: str  # TCP, UDP, ICMP, ARP, DNS or OTHER
    length: int
    sport: int | None = None
    dport: int | None = None
    flags: str = ""  # TCP flags, e.g. "S" for SYN, "SA" for SYN-ACK
    dns_query: str | None = None
    src_mac: str | None = None


@dataclass
class Config:
    port_scan_ports: int = 15  # distinct ports one host probes on another ...
    port_scan_window: float = 10.0  # ... within this many seconds
    syn_flood_count: int = 200  # SYNs to one host ...
    syn_flood_window: float = 5.0  # ... within this many seconds
    heavy_bytes: int = 5_000_000  # bytes one host sends ...
    heavy_window: float = 10.0  # ... within this many seconds
    dns_label_length: int = 40  # a DNS label this long looks like data being smuggled out
    dns_entropy: float = 3.8  # or one this random ...
    dns_entropy_min_length: int = 20  # ... and at least this long
    new_device_warmup: float = 30.0  # devices seen after this point are reported as new
    alert_cooldown: float = 60.0  # do not repeat the same alert within this many seconds
    max_alerts: int = 500


@dataclass
class Alert:
    ts: float
    severity: str  # high, medium, low or info
    kind: str
    source: str
    target: str
    message: str


def shannon_entropy(text: str) -> float:
    """How random a string looks, in bits per character (English words score about 2.5 to 3.5)."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def base_domain(name: str) -> str:
    """The registered domain, e.g. www.uow.edu.au -> uow.edu.au, mail.google.com -> google.com."""
    parts = name.rstrip(".").lower().split(".")
    keep = 3 if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"com", "edu", "gov", "net", "org", "co", "ac"} else 2
    return ".".join(parts[-keep:])


# Address ranges used inside home and office networks (RFC 1918 for IPv4, unique local for IPv6).
# Python's is_private is not used because it also counts documentation and other reserved ranges.
LOCAL_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in LOCAL_NETWORKS)


class _Window:
    """Events inside a sliding time window, with a running total."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.items: deque[tuple[float, object, int]] = deque()
        self.total = 0

    def add(self, ts: float, key=None, amount: int = 1):
        self.items.append((ts, key, amount))
        self.total += amount
        while self.items and self.items[0][0] < ts - self.seconds:
            self.total -= self.items.popleft()[2]

    def distinct_keys(self) -> int:
        return len({key for _, key, _ in self.items})


class Analyzer:
    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.lock = threading.Lock()
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.packets = 0
        self.bytes = 0
        self.protocols: Counter = Counter()
        self.sent: Counter = Counter()
        self.received: Counter = Counter()
        self.dst_ports: Counter = Counter()
        self.dns_domains: Counter = Counter()
        self.timeline: dict[int, list[int]] = {}  # second -> [packets, bytes]
        self.devices: dict[str, dict] = {}
        self.host_peers: dict[str, Counter] = defaultdict(Counter)  # host -> {other host: bytes sent to it}
        self.host_ports: dict[str, Counter] = defaultdict(Counter)  # host -> {port: connections started}
        self.host_dns: dict[str, Counter] = defaultdict(Counter)  # host -> {name looked up: count}
        self.alerts: deque[Alert] = deque(maxlen=self.config.max_alerts)
        self._last_alert: dict[tuple, float] = {}
        self._scan = defaultdict(lambda: _Window(self.config.port_scan_window))
        self._syn = defaultdict(lambda: _Window(self.config.syn_flood_window))
        self._volume = defaultdict(lambda: _Window(self.config.heavy_window))

    # ------------------------------------------------------------------ processing

    def process(self, p: PacketInfo) -> list[Alert]:
        with self.lock:
            return self._process(p)

    def _process(self, p: PacketInfo) -> list[Alert]:
        new_alerts: list[Alert] = []
        if self.first_ts is None:
            self.first_ts = p.ts
        self.last_ts = p.ts

        self.packets += 1
        self.bytes += p.length
        self.protocols[p.proto] += 1
        self.sent[p.src] += p.length
        self.received[p.dst] += p.length
        bucket = self.timeline.setdefault(int(p.ts), [0, 0])
        bucket[0] += 1
        bucket[1] += p.length
        if len(self.timeline) > 600:
            for old in sorted(self.timeline)[:-600]:
                del self.timeline[old]

        self._track_device(p, new_alerts)
        self.host_peers[p.src][p.dst] += p.length

        is_syn = p.proto == "TCP" and "S" in p.flags and "A" not in p.flags
        starts_conversation = is_syn or p.proto in ("UDP", "DNS")

        if p.dport is not None and starts_conversation:
            self.dst_ports[p.dport] += 1
            self.host_ports[p.src][p.dport] += 1

        # Port scan: one host trying many different ports on another host in a short time.
        if p.dport is not None and starts_conversation:
            window = self._scan[(p.src, p.dst)]
            window.add(p.ts, key=p.dport)
            ports = window.distinct_keys()
            if ports >= self.config.port_scan_ports:
                self._alert(new_alerts, p.ts, "high", "Port scan", p.src, p.dst,
                            f"{p.src} probed {ports} different ports on {p.dst} in "
                            f"{self.config.port_scan_window:g} seconds.")

        # SYN flood: a huge number of connection attempts to one host (denial of service).
        if is_syn:
            window = self._syn[p.dst]
            window.add(p.ts)
            if window.total >= self.config.syn_flood_count:
                self._alert(new_alerts, p.ts, "high", "SYN flood", p.src, p.dst,
                            f"{window.total} connection attempts to {p.dst} in "
                            f"{self.config.syn_flood_window:g} seconds (possible denial of service).")

        # Risky or unusual services.
        if p.dport in RISKY_PORTS and starts_conversation:
            self._alert(new_alerts, p.ts, "medium", "Risky port", p.src, f"{p.dst}:{p.dport}",
                        f"{p.src} connected to {p.dst} on port {p.dport} - {RISKY_PORTS[p.dport]}.")

        # Heavy talker: one host sending a lot of data quickly (large upload, possible data theft).
        window = self._volume[p.src]
        window.add(p.ts, amount=p.length)
        if window.total >= self.config.heavy_bytes:
            top_dst, top_bytes = self.host_peers[p.src].most_common(1)[0]
            where = "outside your network" if not is_local(top_dst) else "on your network"
            self._alert(new_alerts, p.ts, "medium", "High traffic", p.src, "any",
                        f"{p.src} sent {window.total / 1_000_000:.1f} MB in "
                        f"{self.config.heavy_window:g} seconds, mostly to {top_dst} ({where}).")

        # Suspicious DNS: very long or random-looking names can hide data (DNS tunnelling) or
        # come from malware that generates domain names.
        if p.dns_query:
            name = p.dns_query.rstrip(".").lower()
            self.dns_domains[base_domain(name)] += 1
            self.host_dns[p.src][name] += 1
            label = max(name.split("."), key=len)
            entropy = shannon_entropy(label)
            if len(label) >= self.config.dns_label_length or (
                len(label) >= self.config.dns_entropy_min_length and entropy >= self.config.dns_entropy
            ):
                base = base_domain(name)
                self._alert(new_alerts, p.ts, "medium", "Suspicious DNS", p.src, base,
                            f"{p.src} looked up a random-looking name ({len(label)} characters, "
                            f"entropy {entropy:.1f}) under {base}. This can be DNS tunnelling or malware.")
        return new_alerts

    def _track_device(self, p: PacketInfo, new_alerts: list[Alert]):
        if not is_local(p.src):
            return
        device = self.devices.get(p.src)
        if device is None:
            device = self.devices[p.src] = {"ip": p.src, "mac": p.src_mac, "first_seen": p.ts,
                                            "last_seen": p.ts, "packets": 0}
            if p.ts - self.first_ts >= self.config.new_device_warmup:
                self._alert(new_alerts, p.ts, "low", "New device", p.src, "network",
                            f"A new device {p.src}" + (f" ({p.src_mac})" if p.src_mac else "")
                            + " joined the network.")
        device["last_seen"] = p.ts
        device["packets"] += 1
        if p.src_mac and not device["mac"]:
            device["mac"] = p.src_mac

    def _alert(self, new_alerts, ts, severity, kind, source, target, message):
        key = (kind, source, target)
        last = self._last_alert.get(key)
        if last is not None and ts - last < self.config.alert_cooldown:
            return
        self._last_alert[key] = ts
        alert = Alert(ts, severity, kind, source, target, message)
        self.alerts.append(alert)
        new_alerts.append(alert)

    # ------------------------------------------------------------------ reporting

    def host_detail(self, ip: str) -> dict:
        """Everything known about one host - used by the AI analyst."""
        with self.lock:
            return {
                "ip": ip,
                "known": ip in self.sent or ip in self.received,
                "local_device": self.devices.get(ip),
                "bytes_sent": self.sent[ip],
                "bytes_received": self.received[ip],
                "sent_to": [{"host": h, "bytes": n} for h, n in self.host_peers[ip].most_common(10)],
                "received_from": sorted(({"host": h, "bytes": peers[ip]} for h, peers in self.host_peers.items()
                                         if peers.get(ip)), key=lambda x: -x["bytes"])[:10],
                "ports_contacted": [{"port": port, "count": n, "risky": port in RISKY_PORTS}
                                    for port, n in self.host_ports[ip].most_common(15)],
                "distinct_ports_contacted": len(self.host_ports[ip]),
                "dns_lookups": [{"name": d, "count": n} for d, n in self.host_dns[ip].most_common(10)],
                "alerts": [asdict(a) for a in self.alerts if ip in (a.source, a.target.split(":")[0])],
            }

    def snapshot(self, timeline_seconds: int = 60) -> dict:
        with self.lock:
            end = int(self.last_ts or 0)
            seconds = list(range(end - timeline_seconds + 1, end + 1)) if self.last_ts else []
            hosts = set(self.sent) | set(self.received)
            talkers = sorted(hosts, key=lambda h: self.sent[h] + self.received[h], reverse=True)[:8]
            alerts = sorted(self.alerts, key=lambda a: a.ts, reverse=True)[:100]
            return {
                "packets": self.packets,
                "bytes": self.bytes,
                "duration": (self.last_ts - self.first_ts) if self.first_ts else 0,
                "last_ts": self.last_ts,
                "protocols": dict(self.protocols.most_common()),
                "timeline": [{"t": s, "packets": self.timeline.get(s, [0, 0])[0],
                              "bytes": self.timeline.get(s, [0, 0])[1]} for s in seconds],
                "top_talkers": [{"host": h, "sent": self.sent[h], "received": self.received[h]}
                                for h in talkers],
                "top_ports": [{"port": port, "count": n, "risky": port in RISKY_PORTS}
                              for port, n in self.dst_ports.most_common(8)],
                "dns": [{"domain": d, "count": n} for d, n in self.dns_domains.most_common(8)],
                "devices": sorted(self.devices.values(), key=lambda d: d["first_seen"]),
                "alert_counts": dict(Counter(a.severity for a in self.alerts)),
                "alerts": [asdict(a) for a in alerts],
            }
