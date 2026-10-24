"""Traffic analysis and detection rules.

The analyser works on simple PacketInfo records, not on raw packets, so it can be tested without capturing
anything and works the same for live traffic and saved .pcap files. All time windows use the packets' own
timestamps, so replaying a capture file gives the same alerts as watching it live.
"""

from __future__ import annotations

import functools
import ipaddress
import math
import statistics
import threading
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field

from .mitre import techniques_for

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

# UDP services that answer from their well-known port (DNS, DHCP, NTP, QUIC/HTTPS, mDNS, SSDP, STUN...).
UDP_SERVICE_PORTS = {53, 67, 68, 69, 123, 137, 138, 161, 443, 500, 514, 853, 1900, 3478, 4500, 5353, 5355, 19302}


def starts_conversation(p) -> bool:
    """Whether a packet opens a new conversation (a connection attempt). TCP: a SYN without ACK. UDP has no
    handshake, so a packet counts unless it is a reply from a service: replies come FROM the service port and go
    TO the client's random port, and counting those made a router answering DNS lookups look like a port scan."""
    if p.proto == "TCP":
        return "S" in p.flags and "A" not in p.flags
    if p.proto in ("UDP", "DNS"):
        if p.sport in UDP_SERVICE_PORTS:
            return False
        return not (p.sport is not None and p.dport is not None and p.sport < 1024 <= p.dport)
    return False


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Services people log in to - many attempts on one of these in a short time looks like password guessing.
LOGIN_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 110: "POP3", 143: "IMAP", 445: "SMB", 1433: "MS SQL",
               3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC"}


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
    dns_answers: tuple = ()  # (name asked, address, name holding the address) from a DNS reply
    tls_sni: str | None = None  # website name from a TLS ClientHello
    ja4: str | None = None  # JA4 fingerprint of the program that opened the TLS connection
    hostname: str | None = None  # name a device gave itself in a DHCP request


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
    brute_force_attempts: int = 20  # connection attempts to one login service ...
    brute_force_window: float = 60.0  # ... within this many seconds
    beacon_min_connections: int = 10  # regular connections to the same outside server ...
    beacon_max_jitter: float = 0.15  # ... whose gaps vary by at most 15% ...
    beacon_min_interval: float = 5.0  # ... and are at least this many seconds apart
    tls_learn_seconds: float = 60.0  # learn which programs (TLS fingerprints) each device uses for this long
    # Content-delivery and cloud networks whose server names look random by design (e1234.dsce9.akadns.net).
    dns_ignore_domains: str = ("akadns.net,akamaiedge.net,akamai.net,edgekey.net,edgesuite.net,akamaized.net,"
                               "cloudflare.net,cloudfront.net,amazonaws.com,azureedge.net,azurefd.net,"
                               "trafficmanager.net,msedge.net,office.net,fastly.net,fastly-edge.com,"
                               "googleusercontent.com,gvt1.com,1e100.net,apple-dns.net,aaplimg.com,cdn-apple.com,"
                               "icloud.com,llnwd.net,edgecastcdn.net,footprint.net")
    watch_countries: str = ""  # comma-separated country codes to alert on, e.g. "KP,IR" (needs GeoIP data)
    alert_cooldown: float = 60.0  # do not repeat the same alert within this many seconds
    max_alerts: int = 500

    def update(self, values: dict) -> dict:
        """Change settings at run time (from the dashboard). Unknown names and bad values are rejected."""
        changed, errors = {}, {}
        for name, raw in values.items():
            if name not in self.__dataclass_fields__ or name == "max_alerts":
                errors[name] = "unknown setting"
                continue
            current = getattr(self, name)
            try:
                if isinstance(current, str):
                    case = str.upper if name == "watch_countries" else str.lower
                    value = ",".join(case(c.strip()) for c in str(raw).split(",") if c.strip())
                else:
                    value = type(current)(raw)
                    if value <= 0 or (name == "beacon_max_jitter" and value >= 1):
                        raise ValueError("must be positive" + (" and below 1" if name == "beacon_max_jitter" else ""))
            except (TypeError, ValueError) as exc:
                errors[name] = str(exc) or "invalid value"
                continue
            setattr(self, name, value)
            changed[name] = value
        return {"changed": changed, "errors": errors}

    def dns_ignored(self, name: str) -> bool:
        """Whether a name belongs to a content-delivery network on the ignore list."""
        name = name.rstrip(".").lower()
        return any(name == d or name.endswith("." + d) for d in self.dns_ignore_domains.split(",") if d)

    def watched(self) -> set[str]:
        return {c for c in self.watch_countries.upper().split(",") if c}


@dataclass
class Alert:
    ts: float
    severity: str  # high, medium, low or info
    kind: str
    source: str
    target: str
    message: str
    mitre: list = field(default_factory=list)  # MITRE ATT&CK techniques, see mitre.py
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    acked: bool = False  # marked as handled on the dashboard
    ack_note: str = ""


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


# Addresses that are never a server on the internet: private ranges (RFC 1918, IPv6 unique local), plus
# loopback, link-local, multicast (e.g. 224.0.0.251, which Macs use to find printers and AirPlay devices) and
# broadcast. Python's is_private is not used because it also counts documentation and other reserved ranges.
LOCAL_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
                                                    "fe80::/10", "ff00::/8", "::1/128")]
_LOCAL_V4_PREFIXES = ("10.", "192.168.", "127.", "169.254.") + tuple(f"172.{n}." for n in range(16, 32)) \
    + tuple(f"{n}." for n in range(224, 240))


@functools.lru_cache(maxsize=65536)
def _is_local_v6(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in LOCAL_NETWORKS)


def is_local(ip: str) -> bool:
    """True for addresses on your own network (or multicast/broadcast), False for servers on the internet."""
    if ":" in ip:  # IPv6 (or a MAC address, which is not an IP and gives False)
        return _is_local_v6(ip)
    # IPv4 addresses come from packet parsers as dotted decimal, so a prefix check is exact and much faster.
    return ip.startswith(_LOCAL_V4_PREFIXES) or ip == "255.255.255.255"


class _Window:
    """Events inside a sliding time window, with a running total."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.items: deque[tuple[float, object, int]] = deque()
        self.total = 0
        self.keys: Counter = Counter()  # how often each key is in the window, so distinct_keys() is O(1)

    def add(self, ts: float, key=None, amount: int = 1):
        self.items.append((ts, key, amount))
        self.total += amount
        self.keys[key] += 1
        while self.items and self.items[0][0] < ts - self.seconds:
            _, old, n = self.items.popleft()
            self.total -= n
            self.keys[old] -= 1
            if not self.keys[old]:
                del self.keys[old]

    def distinct_keys(self) -> int:
        return len(self.keys)


class Analyzer:
    def __init__(self, config: Config | None = None, intel=None, ml=None, geo=None, privacy=None):
        from .privacy import PrivacyTracker

        self.config = config or Config()
        self.intel = intel  # ThreatIntel blocklists (optional)
        self.ml = ml  # AnomalyDetector (optional)
        self.geo = geo  # GeoIP country lookup (optional)
        self.listeners: list = []  # called with each new alert (history database, notifications)
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
        self.dns_servers: Counter = Counter()  # local addresses that answer DNS lookups (usually the router)
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
        self._login = defaultdict(lambda: _Window(self.config.brute_force_window))
        self._beacon: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=24))
        self.ip_mac: dict[str, str] = {}  # local IP -> MAC address it was first seen with
        self._country_alerted: set = set()
        self.privacy = privacy if privacy is not None else PrivacyTracker(geo)  # see privacy.py
        self.tls_clients: dict[str, Counter] = defaultdict(Counter)  # device -> {JA4 fingerprint: connections}
        self.tls_first: dict[str, float] = {}  # device -> when its first TLS connection was seen

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
        self._check_arp(p, new_alerts)
        if self.intel is not None:
            self._check_intel(p, new_alerts)
        if self.ml is not None:
            for anomaly in self.ml.observe(p):
                self._ml_alert(anomaly, new_alerts)
        self.host_peers[p.src][p.dst] += p.length
        self.privacy.observe(p)
        if p.ja4:
            self._check_tls(p, new_alerts)

        is_syn = p.proto == "TCP" and "S" in p.flags and "A" not in p.flags
        starts = starts_conversation(p)

        if p.dport is not None and starts:
            self.dst_ports[p.dport] += 1
            self.host_ports[p.src][p.dport] += 1

        # Port scan: one host trying many different ports on another host in a short time.
        if p.dport is not None and starts:
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

        # Brute force: many connection attempts to one login service (password guessing).
        if is_syn and p.dport in LOGIN_PORTS:
            window = self._login[(p.src, p.dst, p.dport)]
            window.add(p.ts)
            if window.total >= self.config.brute_force_attempts:
                self._alert(new_alerts, p.ts, "high", "Brute force", p.src, f"{p.dst}:{p.dport}",
                            f"{p.src} made {window.total} connection attempts to {LOGIN_PORTS[p.dport]} "
                            f"(port {p.dport}) on {p.dst} in {self.config.brute_force_window:g} seconds - "
                            "possible password guessing.")

        # Beaconing: malware "calling home" to its server on a fixed timer.
        if starts and p.proto != "DNS" and is_local(p.src) and not is_local(p.dst):
            self._check_beacon(p, new_alerts)

        # Countries the owner asked to be warned about.
        if self.geo is not None and self.config.watch_countries and is_local(p.src) and not is_local(p.dst):
            country = self.geo.country(p.dst)
            if country and country in self.config.watched() and (p.src, p.dst) not in self._country_alerted:
                self._country_alerted.add((p.src, p.dst))
                self._alert(new_alerts, p.ts, "medium", "Watched country", p.src, p.dst,
                            f"{p.src} connected to {p.dst} in {country}, a country on your watch list.")

        # Risky or unusual services.
        if p.dport in RISKY_PORTS and starts:
            self._alert(new_alerts, p.ts, "medium", "Risky port", p.src, f"{p.dst}:{p.dport}",
                        f"{p.src} connected to {p.dst} on port {p.dport} - {RISKY_PORTS[p.dport]}.", port=p.dport)

        # Heavy talker: one of your devices sending a lot of data quickly (large upload, possible data theft).
        # Outside servers sending a lot TO you is just a download (video, updates), so they are not counted.
        window = self._volume[p.src] if is_local(p.src) else None
        if window is not None:
            window.add(p.ts, amount=p.length)
        if window is not None and window.total >= self.config.heavy_bytes:
            top_dst, top_bytes = self.host_peers[p.src].most_common(1)[0]
            where = "outside your network" if not is_local(top_dst) else "on your network"
            self._alert(new_alerts, p.ts, "medium", "High traffic", p.src, "any",
                        f"{p.src} sent {window.total / 1_000_000:.1f} MB in "
                        f"{self.config.heavy_window:g} seconds, mostly to {top_dst} ({where}).")

        # Suspicious DNS: very long or random-looking names can hide data (DNS tunnelling) or
        # come from malware that generates domain names.
        if p.dns_query:
            name = p.dns_query.rstrip(".").lower()
            if is_local(p.dst):
                self.dns_servers[p.dst] += 1
            self.dns_domains[base_domain(name)] += 1
            self.host_dns[p.src][name] += 1
            label = max(name.split("."), key=len)
            entropy = shannon_entropy(label)
            if self.config.dns_ignored(name):
                pass
            elif len(label) >= self.config.dns_label_length or (
                len(label) >= self.config.dns_entropy_min_length and entropy >= self.config.dns_entropy
            ):
                base = base_domain(name)
                self._alert(new_alerts, p.ts, "medium", "Suspicious DNS", p.src, base,
                            f"{p.src} looked up a random-looking name ({len(label)} characters, "
                            f"entropy {entropy:.1f}) under {base}. This can be DNS tunnelling or malware.")
        return new_alerts

    def _check_arp(self, p: PacketInfo, new_alerts: list[Alert]):
        """ARP spoofing: a second device claims an IP address that already belongs to another device. This is
        how attackers put themselves in the middle of other people's traffic (often claiming the router)."""
        if not p.src_mac or not is_local(p.src) or p.src_mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return
        mac = p.src_mac.lower()
        known = self.ip_mac.get(p.src)
        if known is None:
            self.ip_mac[p.src] = mac
        elif known != mac and p.proto == "ARP":
            self._alert(new_alerts, p.ts, "high", "ARP spoofing", mac, p.src,
                        f"Device {mac} claims to be {p.src}, which belongs to {known} - possible "
                        "man-in-the-middle attack (ARP spoofing).")

    def _check_beacon(self, p: PacketInfo, new_alerts: list[Alert]):
        times = self._beacon[(p.src, p.dst)]
        if times and p.ts - times[-1] < 1.0:  # the same connection (retries, several packets)
            return
        times.append(p.ts)
        if len(times) < self.config.beacon_min_connections:
            return
        recent = list(times)[-self.config.beacon_min_connections:]
        gaps = [b - a for a, b in zip(recent, recent[1:])]
        mean = statistics.mean(gaps)
        if mean < self.config.beacon_min_interval:
            return
        jitter = statistics.pstdev(gaps) / mean
        if jitter <= self.config.beacon_max_jitter:
            self._alert(new_alerts, p.ts, "medium", "Beaconing", p.src, p.dst,
                        f"{p.src} connects to {p.dst} every {mean:.0f} seconds like clockwork "
                        f"({len(recent)} times, timing varies only {jitter * 100:.0f}%) - malware often "
                        "\"calls home\" to its server on a timer.", cooldown=1800)  # once per 30 minutes

    def _check_tls(self, p: PacketInfo, new_alerts: list[Alert]):
        """Encrypted traffic: HTTPS hides the content, but the ClientHello's JA4 fingerprint shows which program
        opened the connection. Two checks:
        1. The fingerprint is on a threat-intelligence list (a known malware or attack tool).
        2. After a learning period, a device uses a program it has never used before, to an outside server,
           without naming a website (no SNI). Browsers and apps almost always name the site; malware and
           remote-access tools connecting to a bare IP address often do not."""
        if self.intel is not None and p.ja4 in getattr(self.intel, "ja4", {}):
            self._alert(new_alerts, p.ts, "high", "Threat intel", p.src, p.dst,
                        f"{p.src} opened an encrypted connection to {p.dst} with a program whose TLS fingerprint "
                        f"({p.ja4}) is on the blocklist \"{self.intel.ja4[p.ja4]}\".")
        if not is_local(p.src):
            return
        seen = self.tls_clients[p.src]
        first = self.tls_first.setdefault(p.src, p.ts)
        new = p.ja4 not in seen
        seen[p.ja4] += 1
        if (new and not p.tls_sni and not is_local(p.dst) and p.ts - first >= self.config.tls_learn_seconds
                and len(seen) > 1):
            self._alert(new_alerts, p.ts, "medium", "Unusual TLS client", p.src, p.dst,
                        f"{p.src} opened an encrypted connection to {p.dst} with a program it has not used before "
                        f"(TLS fingerprint {p.ja4}) and without naming a website. Browsers and apps almost always "
                        "name the site; malware and remote-access tools often do not.")

    def _ml_alert(self, a: dict, new_alerts: list[Alert]):
        self._alert(new_alerts, a["ts"], "medium", "Anomaly (ML)", a["host"], "behaviour",
                    f"Machine learning flagged {a['host']} as unusual (anomaly score {a['score']}): "
                    + "; ".join(a["reasons"]) + ".")

    def finish(self) -> list[Alert]:
        """Call when a capture file ends, so the last time window is analysed too."""
        new_alerts: list[Alert] = []
        if self.ml is not None:
            with self.lock:
                for anomaly in self.ml.flush():
                    self._ml_alert(anomaly, new_alerts)
        return new_alerts

    def _check_intel(self, p: PacketInfo, new_alerts: list[Alert]):
        """Traffic to or from an address on a threat-intelligence blocklist, or a lookup of a listed domain."""
        for remote, local, direction in ((p.dst, p.src, "sent traffic to"), (p.src, p.dst, "received traffic from")):
            if is_local(remote):
                continue
            listed = self.intel.match_ip(remote)
            if listed:
                self._alert(new_alerts, p.ts, "high", "Threat intel", local, remote,
                            f"{local} {direction} {remote}, which is on the blocklist "
                            f"\"{listed}\".")
        if p.dns_query:
            hit = self.intel.match_domain(p.dns_query)
            if hit:
                domain, listed = hit
                self._alert(new_alerts, p.ts, "high", "Threat intel", p.src, domain,
                            f"{p.src} looked up {domain}, which is on the blocklist \"{listed}\".")

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
        if p.hostname:
            device["hostname"] = p.hostname
        if p.src_mac and not device["mac"]:
            device["mac"] = p.src_mac

    def _alert(self, new_alerts, ts, severity, kind, source, target, message, port=None, cooldown=None):
        key = (kind, source, target)
        last = self._last_alert.get(key)
        if last is not None and ts - last < max(self.config.alert_cooldown, cooldown or 0):
            return
        self._last_alert[key] = ts
        alert = Alert(ts, severity, kind, source, target, message, techniques_for(kind, port))
        self.alerts.append(alert)
        new_alerts.append(alert)
        for listener in self.listeners:
            try:
                listener(alert)
            except Exception:  # a broken listener (e.g. a full disk) must never stop the monitor
                pass

    def update_config(self, values: dict) -> dict:
        """Change detection settings while running; time windows restart so the new limits apply at once."""
        with self.lock:
            result = self.config.update(values)
            if result["changed"]:
                for windows in (self._scan, self._syn, self._volume, self._login):
                    windows.clear()
                self._country_alerted.clear()
            return result

    def acknowledge(self, alert_id: str, note: str = "", acked: bool = True) -> Alert | None:
        with self.lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.acked, alert.ack_note = acked, note[:500]
                    return alert
        return None

    def gateway(self) -> str | None:
        """The router: the local address devices send their DNS lookups to, or else the one ending in .1."""
        if self.dns_servers:
            return self.dns_servers.most_common(1)[0][0]
        return next((ip for ip in self.devices if ip.endswith(".1")), None)

    def country(self, ip: str) -> str | None:
        return self.geo.country(ip) if self.geo is not None and not is_local(ip) else None

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
                "country": self.country(ip),
                "dns_lookups": [{"name": d, "count": n} for d, n in self.host_dns[ip].most_common(10)],
                "tls_programs": [{"ja4": j, "connections": n} for j, n in self.tls_clients.get(ip, Counter()).most_common(8)],
                "alerts": [asdict(a) for a in self.alerts if ip in (a.source, a.target.split(":")[0])],
            }

    def _links(self, limit: int = 40) -> list[dict]:
        """Who talks to whom (both directions added together), largest first - for the network map."""
        pairs: Counter = Counter()
        for src, peers in self.host_peers.items():
            for dst, n in peers.items():
                if src != dst and (is_local(src) or is_local(dst)):
                    pairs[tuple(sorted((src, dst)))] += n
        return [{"a": a, "b": b, "bytes": n} for (a, b), n in pairs.most_common(limit)]

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
                "top_talkers": [{"host": h, "sent": self.sent[h], "received": self.received[h],
                                 "country": self.country(h)} for h in talkers],
                "top_ports": [{"port": port, "count": n, "risky": port in RISKY_PORTS}
                              for port, n in self.dst_ports.most_common(8)],
                "dns": [{"domain": d, "count": n} for d, n in self.dns_domains.most_common(8)],
                "devices": sorted(self.devices.values(), key=lambda d: d["first_seen"]),
                "links": self._links(),
                "alert_counts": dict(Counter(a.severity for a in self.alerts)),
                "intel": self.intel.summary() if self.intel is not None else None,
                "ml": self.ml.status() if self.ml is not None else None,
                "geo": self.geo.summary() if self.geo is not None else None,
                "config": asdict(self.config),
                "alerts": [asdict(a) for a in alerts],
            }
