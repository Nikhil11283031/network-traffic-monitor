"""Privacy X-ray: which companies and countries each device on your network sends data to.

Smart TVs, phones and apps quietly report to advertisers, analytics companies and manufacturers. This module
works out who each outside address belongs to, using only details that are sent unencrypted:
1. DNS replies: the device asked "where is samsungacr.com?" and got an address back.
2. The website name (SNI) at the start of every HTTPS connection.
3. Optionally the country of the address (GeoIP, `python3 -m netmon update-geoip`).
Names are then matched to companies and categories (advertising, analytics, TV viewing tracking...) from a
built-in list, extendable with Disconnect's open tracker list (`python3 -m netmon update-privacy`).

Nothing is decrypted: it sees *who* a device talks to and how much, never *what* it says.
"""

from __future__ import annotations

import json
import threading
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

from .analyzer import PacketInfo, base_domain, is_local

# Categories: what it means and what you can do about it.
CATEGORIES = {
    "tv-tracking": ("TV viewing tracking", "high",
                    "Records what is on screen (automatic content recognition) to build an advertising profile.",
                    "Turn off 'Viewing information', 'Live Plus', 'ACR' or 'Smart interactivity' in the TV's "
                    "privacy settings."),
    "advertising": ("Advertising", "medium", "Ad networks that track you across apps and websites.",
                    "Limit ad tracking in the device settings, or block the domain with Pi-hole or your router."),
    "analytics": ("Analytics", "medium", "Usage reporting about what you do inside apps and websites.",
                  "Turn off 'share usage data' / 'analytics' in the app or device settings."),
    "telemetry": ("Telemetry", "low", "Diagnostic and usage data sent to the manufacturer.",
                  "Most systems let you reduce it under privacy or diagnostics settings."),
    "social": ("Social network", "medium", "Social networks; their trackers also appear inside other apps.",
               "Check which apps are allowed to share data with this network."),
    "fingerprinting": ("Fingerprinting", "high", "Identifies a device without cookies, so it is hard to opt out.",
                       "Block the domain with Pi-hole or your router's DNS filter."),
    "service": ("Service", "info", "The service itself (streaming, cloud, updates).", ""),
}

# Base domain -> (company, category). A hand-made starter list of well-known names; Disconnect's list adds more.
KNOWN = {
    # TV viewing tracking (ACR)
    "samsungacr.com": ("Samsung", "tv-tracking"), "samsungads.com": ("Samsung", "advertising"),
    "samsungcloudsolution.com": ("Samsung", "telemetry"), "samsungcloudsolution.net": ("Samsung", "telemetry"),
    "samsungqbe.com": ("Samsung", "telemetry"), "samsungelectronics.com": ("Samsung", "service"),
    "lgtvsdp.com": ("LG", "telemetry"), "lgsmartad.com": ("LG", "advertising"), "lgads.tv": ("LG", "advertising"),
    "alphonso.tv": ("LG (Alphonso)", "tv-tracking"), "samba.tv": ("Samba TV", "tv-tracking"),
    "inscape.tv": ("Vizio (Inscape)", "tv-tracking"), "vizio.com": ("Vizio", "service"),
    "roku.com": ("Roku", "service"), "ravm.tv": ("Roku", "advertising"), "logs.roku.com": ("Roku", "telemetry"),
    "tvinteractive.tv": ("Samsung", "tv-tracking"),
    # Advertising
    "doubleclick.net": ("Google", "advertising"), "googlesyndication.com": ("Google", "advertising"),
    "googleadservices.com": ("Google", "advertising"), "googletagservices.com": ("Google", "advertising"),
    "adservice.google.com": ("Google", "advertising"), "admob.com": ("Google", "advertising"),
    "amazon-adsystem.com": ("Amazon", "advertising"), "criteo.com": ("Criteo", "advertising"),
    "criteo.net": ("Criteo", "advertising"), "taboola.com": ("Taboola", "advertising"),
    "outbrain.com": ("Outbrain", "advertising"), "adnxs.com": ("Microsoft (Xandr)", "advertising"),
    "rubiconproject.com": ("Magnite", "advertising"), "pubmatic.com": ("PubMatic", "advertising"),
    "openx.net": ("OpenX", "advertising"), "applovin.com": ("AppLovin", "advertising"),
    "unityads.unity3d.com": ("Unity", "advertising"), "moatads.com": ("Oracle (Moat)", "advertising"),
    "ads-twitter.com": ("X (Twitter)", "advertising"), "ads.linkedin.com": ("LinkedIn", "advertising"),
    "tiktokv.com": ("ByteDance (TikTok)", "social"), "tiktok.com": ("ByteDance (TikTok)", "social"),
    "byteoversea.com": ("ByteDance (TikTok)", "telemetry"), "ibytedtos.com": ("ByteDance (TikTok)", "service"),
    # Analytics
    "google-analytics.com": ("Google", "analytics"), "googletagmanager.com": ("Google", "analytics"),
    "app-measurement.com": ("Google (Firebase)", "analytics"), "crashlytics.com": ("Google (Firebase)", "telemetry"),
    "firebaselogging-pa.googleapis.com": ("Google (Firebase)", "analytics"),
    "scorecardresearch.com": ("Comscore", "analytics"), "hotjar.com": ("Hotjar", "analytics"),
    "mixpanel.com": ("Mixpanel", "analytics"), "segment.io": ("Segment", "analytics"),
    "segment.com": ("Segment", "analytics"), "amplitude.com": ("Amplitude", "analytics"),
    "branch.io": ("Branch", "analytics"), "appsflyer.com": ("AppsFlyer", "analytics"),
    "adjust.com": ("Adjust", "analytics"), "kochava.com": ("Kochava", "analytics"),
    "clarity.ms": ("Microsoft (Clarity)", "analytics"), "newrelic.com": ("New Relic", "telemetry"),
    "sentry.io": ("Sentry", "telemetry"), "bugsnag.com": ("Bugsnag", "telemetry"),
    "eulerian.net": ("Eulerian", "analytics"), "fingerprintjs.com": ("FingerprintJS", "fingerprinting"),
    "fpjs.io": ("FingerprintJS", "fingerprinting"),
    # Telemetry
    "events.data.microsoft.com": ("Microsoft", "telemetry"), "vortex.data.microsoft.com": ("Microsoft", "telemetry"),
    "telemetry.microsoft.com": ("Microsoft", "telemetry"), "device-metrics-us.amazon.com": ("Amazon", "telemetry"),
    "device-metrics-us-2.amazon.com": ("Amazon", "telemetry"), "metrics.icloud.com": ("Apple", "telemetry"),
    "xp.apple.com": ("Apple", "telemetry"), "tracking.miui.com": ("Xiaomi", "telemetry"),
    "data.mistat.xiaomi.com": ("Xiaomi", "telemetry"), "hicloud.com": ("Huawei", "telemetry"),
    "telemetry.mozilla.org": ("Mozilla", "telemetry"),
    # Social
    "facebook.com": ("Meta", "social"), "facebook.net": ("Meta", "social"), "fbcdn.net": ("Meta", "social"),
    "graph.facebook.com": ("Meta", "social"), "instagram.com": ("Meta", "social"), "cdninstagram.com": ("Meta", "social"),
    "whatsapp.net": ("Meta", "service"), "whatsapp.com": ("Meta", "service"), "twitter.com": ("X (Twitter)", "social"),
    "x.com": ("X (Twitter)", "social"), "snapchat.com": ("Snap", "social"), "linkedin.com": ("LinkedIn", "social"),
    # Services (named so the report reads well)
    "google.com": ("Google", "service"), "googleapis.com": ("Google", "service"), "gstatic.com": ("Google", "service"),
    "youtube.com": ("Google (YouTube)", "service"), "googlevideo.com": ("Google (YouTube)", "service"),
    "ytimg.com": ("Google (YouTube)", "service"), "apple.com": ("Apple", "service"), "icloud.com": ("Apple", "service"),
    "mzstatic.com": ("Apple", "service"), "netflix.com": ("Netflix", "service"), "nflxvideo.net": ("Netflix", "service"),
    "nflximg.net": ("Netflix", "service"), "microsoft.com": ("Microsoft", "service"), "live.com": ("Microsoft", "service"),
    "office.com": ("Microsoft", "service"), "windowsupdate.com": ("Microsoft", "service"),
    "amazon.com": ("Amazon", "service"), "amazonaws.com": ("Amazon (AWS)", "service"),
    "cloudfront.net": ("Amazon (AWS)", "service"), "akamaiedge.net": ("Akamai", "service"),
    "akamaized.net": ("Akamai", "service"), "cloudflare.com": ("Cloudflare", "service"),
    "github.com": ("GitHub", "service"), "spotify.com": ("Spotify", "service"),
    "dropbox.com": ("Dropbox", "service"), "zoom.us": ("Zoom", "service"),
}


def classify(name: str, extra: dict | None = None) -> tuple[str, str]:
    """(company, category) for a domain name. Longest matching suffix wins, so ads.linkedin.com is advertising
    while linkedin.com is social. Unknown names get their own domain as company and category 'service'."""
    name = name.rstrip(".").lower()
    parts = name.split(".")
    for i in range(len(parts) - 1):
        suffix = ".".join(parts[i:])
        for table in (extra or {}, KNOWN):
            if suffix in table:
                return table[suffix]
    return base_domain(name), "service"


def load_disconnect(path: str | Path) -> dict:
    """Read Disconnect's services.json (https://github.com/disconnectme/disconnect-tracking-protection) into
    {domain: (company, category)}."""
    mapping = {"Advertising": "advertising", "Analytics": "analytics", "Social": "social",
               "FingerprintingInvasive": "fingerprinting", "FingerprintingGeneral": "fingerprinting",
               "Cryptomining": "fingerprinting", "Email": "analytics", "EmailAggressive": "analytics",
               "Content": None, "Disconnect": None, "Anti-fraud": None, "ConsentManagers": None}
    data = json.loads(Path(path).read_text())
    out = {}
    for cat_name, entries in data.get("categories", {}).items():
        category = mapping.get(cat_name, "advertising")
        if category is None:
            continue
        for entry in entries:
            for company, sites in entry.items():
                for _home, domains in sites.items():
                    if isinstance(domains, list):
                        for domain in domains:
                            out.setdefault(str(domain).lower(), (company, category))
    return out


class _LRU(OrderedDict):
    def __init__(self, limit: int):
        super().__init__()
        self.limit = limit

    def put(self, key, value):
        self[key] = value
        self.move_to_end(key)
        if len(self) > self.limit:
            self.popitem(last=False)


class PrivacyTracker:
    """Keeps, per local device, how much it sent to and received from each outside party."""

    def __init__(self, geo=None, extra: dict | None = None):
        self.geo = geo
        self.extra = extra or {}
        self.lock = threading.Lock()
        self.names = _LRU(100_000)  # outside address -> name (from DNS replies and TLS SNI)
        self.cloaked = _LRU(20_000)  # address -> (name the site used, tracker name it really points to)
        self.flows: dict[str, dict[str, list]] = defaultdict(dict)  # device -> {address: [bytes out, bytes in]}
        self.lookups: dict[str, Counter] = defaultdict(Counter)  # device -> {name looked up: count}
        self.hostnames: dict[str, str] = {}  # device -> name from DHCP

    def observe(self, p: PacketInfo):
        with self.lock:
            for asked, ip, holder in p.dns_answers:
                self.names.put(ip, asked)
                if holder != asked and classify(holder, self.extra)[1] != "service" \
                        and classify(asked, self.extra)[1] == "service":
                    self.cloaked.put(ip, (asked, holder))
            if p.hostname and is_local(p.src):
                self.hostnames[p.src] = p.hostname
            if p.dns_query and is_local(p.src):
                self.lookups[p.src][p.dns_query.rstrip(".").lower()] += 1
            local_src, local_dst = is_local(p.src), is_local(p.dst)
            if local_src and not local_dst:
                if p.tls_sni:
                    self.names.put(p.dst, p.tls_sni)
                entry = self.flows[p.src].setdefault(p.dst, [0, 0])
                entry[0] += p.length
            elif local_dst and not local_src:
                entry = self.flows[p.dst].setdefault(p.src, [0, 0])
                entry[1] += p.length

    # ------------------------------------------------------------------ report

    def _party(self, ip: str) -> tuple[str, str, str | None, str | None]:
        """(company, category, name, cloaked-tracker name) for an outside address."""
        name = self.names.get(ip)
        cloak = self.cloaked.get(ip)
        if cloak:
            company, category = classify(cloak[1], self.extra)
            return company, category, cloak[0], cloak[1]
        if name:
            company, category = classify(name, self.extra)
            return company, category, name, None
        return "Unidentified", "service", None, None

    def report(self, devices: list[str] | None = None) -> dict:
        with self.lock:
            out = []
            for device in devices or sorted(self.flows):
                parties: dict[str, dict] = {}
                for ip, (sent, received) in self.flows.get(device, {}).items():
                    company, category, name, cloak = self._party(ip)
                    country = self.geo.country(ip) if self.geo is not None else None
                    key = f"{company}|{category}"
                    party = parties.setdefault(key, {"company": company, "category": category, "sent": 0,
                                                     "received": 0, "domains": Counter(), "countries": Counter(),
                                                     "addresses": 0, "cloaked": set()})
                    party["sent"] += sent
                    party["received"] += received
                    party["addresses"] += 1
                    if name:
                        party["domains"][name] += sent + received + 1
                    if country:
                        party["countries"][country] += sent + received
                    if cloak:
                        party["cloaked"].add(f"{name} -> {cloak}")
                rows = []
                for party in parties.values():
                    label, risk, meaning, tip = CATEGORIES[party["category"]]
                    rows.append({"company": party["company"], "category": party["category"], "category_label": label,
                                 "risk": risk, "sent": party["sent"], "received": party["received"],
                                 "domains": [d for d, _ in party["domains"].most_common(5)],
                                 "countries": [c for c, _ in party["countries"].most_common(3)],
                                 "addresses": party["addresses"], "cloaked": sorted(party["cloaked"]),
                                 "meaning": meaning, "tip": tip})
                rows.sort(key=lambda r: (r["category"] == "service", -r["sent"]))
                trackers = [r for r in rows if r["category"] != "service"]
                sent_total = sum(r["sent"] for r in rows)
                total = sent_total or 1  # avoid dividing by zero for a device that only downloaded
                out.append({"device": device, "hostname": self.hostnames.get(device), "kind": self._guess(rows),
                            "companies": len({r["company"] for r in rows if r["company"] != "Unidentified"}),
                            "trackers": len(trackers), "sent": sent_total,
                            "tracker_share": round(sum(r["sent"] for r in trackers) / total, 3),
                            "countries": sorted({c for r in rows for c in r["countries"]}),
                            "parties": rows[:25]})
            out.sort(key=lambda d: (-d["trackers"], -d["sent"]))
            return {"devices": out, "findings": self._findings(out), "names_known": len(self.names),
                    "countries_known": self.geo is not None,
                    "extra_list": len(self.extra)}

    @staticmethod
    def _guess(rows) -> str | None:
        """A device type only when the evidence is strong (TV-maker tracking services)."""
        tv_makers = ("Samsung", "LG", "Roku", "Vizio", "Samba TV")
        if any(r["category"] == "tv-tracking" or (r["company"].startswith(tv_makers) and r["category"] != "service")
               for r in rows):
            return "Smart TV"
        return None

    @staticmethod
    def _findings(devices) -> list[dict]:
        """Plain-language highlights, most important first."""
        findings = []
        rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
        for d in devices:
            who = d["hostname"] or d["kind"]
            who = f"{who} ({d['device']})" if who else d["device"]
            for r in d["parties"]:
                if r["category"] == "service":
                    continue
                label = r["category_label"] if r["category_label"].startswith("TV") else r["category_label"].lower()
                text = (f"{who} sent {_size(r['sent'])} to {r['company']} - {label}" + (f" ({', '.join(r['domains'][:2])})" if r["domains"] else "")
                        + (f", servers in {', '.join(r['countries'])}" if r["countries"] else "") + ".")
                tip = r["tip"]
                if r["cloaked"]:
                    text += f" Hidden behind the site's own name (CNAME cloaking): {r['cloaked'][0]}."
                    tip = ("Ordinary ad blockers miss cloaked trackers; a DNS filter that checks CNAMEs (for example "
                           "NextDNS or AdGuard DNS) blocks them.")
                findings.append({"device": d["device"], "severity": "high" if r["cloaked"] else r["risk"],
                                 "text": text, "tip": tip})
        findings.sort(key=lambda f: rank[f["severity"]])
        return findings[:30]


def _size(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1000:
        return f"{n / 1000:.0f} KB"
    return f"{n} bytes"


DISCONNECT_URL = ("https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/"
                  "services.json")


def update_list(folder: str | Path = "privacy") -> str:
    """Download Disconnect's open tracker list (thousands of tracker domains, by company and category)."""
    import ssl
    import urllib.request

    try:
        import certifi
        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(DISCONNECT_URL, headers={"User-Agent": "netmon"})
    with urllib.request.urlopen(req, timeout=60, context=context) as resp:
        body = resp.read()
    target = folder / "disconnect-services.json"
    target.write_bytes(body)
    return f"saved {len(load_disconnect(target)):,} tracker domains to {target}"


def load_extra(folder: str | Path = "privacy") -> dict:
    path = Path(folder) / "disconnect-services.json"
    try:
        return load_disconnect(path) if path.exists() else {}
    except (ValueError, OSError):
        return {}
