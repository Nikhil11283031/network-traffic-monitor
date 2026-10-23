"""Threat intelligence: checking traffic against public blocklists of known-bad servers.

Security researchers publish free lists of IP addresses and domains that are known to run malware command
servers, spread malware or belong to criminal networks. If a device on your network talks to one of them, that
is a strong sign something is wrong - much stronger than a threshold rule.

Lists live as text files in the intel/ folder. `python3 -m netmon update-intel` downloads the free feeds below.
Each file may contain, one per line: an IP address, a CIDR range (e.g. 203.0.113.0/24), a domain name, a hosts-file
line ("127.0.0.1 bad.example") or a JSON line with a "cidr" field (Spamhaus format). Lines starting with # or ;
are comments. The first "# name: ..." comment, if present, is used as the list's display name.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FEEDS = {
    "feodo": ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
              "abuse.ch Feodo Tracker - botnet command-and-control servers"),
    "spamhaus-drop": ("https://www.spamhaus.org/drop/drop_v4.json",
                      "Spamhaus DROP - hijacked and criminal networks"),
    # abuse.ch retired its URLhaus hosts file (HTTP 410), so use the malware-filter project's domain list built
    # from URLhaus data. Several mirrors are tried in order.
    "urlhaus": (["https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt",
                 "https://curbengh.github.io/malware-filter/urlhaus-filter-hosts-online.txt",
                 "https://malware-filter.pages.dev/urlhaus-filter-hosts-online.txt"],
                "URLhaus (via malware-filter) - domains spreading malware"),
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
SKIP_DOMAINS = {"localhost", "localhost.localdomain", "local", "broadcasthost"}


class ThreatIntel:
    def __init__(self):
        self.ips: dict[str, str] = {}  # exact IP -> list name
        self.networks: list[tuple[ipaddress._BaseNetwork, str]] = []
        self.domains: dict[str, str] = {}
        self.lists: dict[str, int] = {}  # list name -> number of entries
        self._ip_cache: dict[str, str | None] = {}

    @property
    def size(self) -> int:
        return len(self.ips) + len(self.networks) + len(self.domains)

    def load_dir(self, folder: str | Path) -> "ThreatIntel":
        folder = Path(folder)
        if folder.is_dir():
            for path in sorted(folder.glob("*.txt")):
                self.load_file(path)
        return self

    def load_file(self, path: str | Path, name: str | None = None) -> int:
        path = Path(path)
        return self.load_text(path.read_text(errors="replace"), name or path.stem)

    def load_text(self, text: str, name: str) -> int:
        entries = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line[0] in "#;":
                match = re.match(r"[#;]\s*name:\s*(.+)", line, re.I)
                if match and not entries:
                    name = match.group(1).strip()
                continue
            if line.startswith("{"):  # Spamhaus JSON lines
                try:
                    value = json.loads(line).get("cidr")
                except json.JSONDecodeError:
                    value = None
                if value:
                    entries.append(value)
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("127.0.0.1", "0.0.0.0"):  # hosts-file format
                entries.append(parts[1])
            else:
                entries.append(parts[0].split(";")[0])
        added = 0
        for value in entries:
            added += self._add(value.strip().lower(), name)
        if added:
            self.lists[name] = self.lists.get(name, 0) + added
            self._ip_cache.clear()
        return added

    def _add(self, value: str, name: str) -> int:
        try:
            if "/" in value:
                net = ipaddress.ip_network(value, strict=False)
                if net.num_addresses == 1:
                    self.ips[str(net.network_address)] = name
                else:
                    self.networks.append((net, name))
                return 1
            self.ips[str(ipaddress.ip_address(value))] = name
            return 1
        except ValueError:
            pass
        value = value.rstrip(".")
        if value not in SKIP_DOMAINS and DOMAIN_RE.match(value):
            self.domains[value] = name
            return 1
        return 0

    def match_ip(self, ip: str) -> str | None:
        """The list an IP address is on, or None."""
        if ip in self._ip_cache:
            return self._ip_cache[ip]
        found = self.ips.get(ip)
        if found is None and self.networks:
            try:
                addr = ipaddress.ip_address(ip)
                found = next((name for net, name in self.networks if addr in net), None)
            except ValueError:
                found = None
        if len(self._ip_cache) > 50_000:
            self._ip_cache.clear()
        self._ip_cache[ip] = found
        return found

    def match_domain(self, name: str) -> tuple[str, str] | None:
        """(listed domain, list name) if the name or any parent domain is listed."""
        labels = name.rstrip(".").lower().split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self.domains:
                return candidate, self.domains[candidate]
        return None

    def summary(self) -> dict:
        return {"indicators": self.size, "lists": dict(self.lists)}


def _ssl_context():
    """Trusted certificates for HTTPS downloads. The python.org installer on macOS ships without any, which
    causes CERTIFICATE_VERIFY_FAILED, so use certifi's certificate bundle when it is installed."""
    import ssl

    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def update_feeds(folder: str | Path = "intel", feeds: dict | None = None, timeout: float = 60) -> list[str]:
    """Download the free feeds into folder/<key>.txt. Returns one status line per feed."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    report = []
    context = _ssl_context()
    for key, (urls, title) in (feeds or FEEDS).items():
        errors = []
        for url in [urls] if isinstance(urls, str) else urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "netmon (network traffic monitor)"})
                with urllib.request.urlopen(req, timeout=timeout, context=context) as res:
                    body = res.read().decode("utf-8", errors="replace")
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
                continue
            count = ThreatIntel().load_text(body, title)
            if count == 0:
                errors.append("downloaded but no entries found")
                continue
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            (folder / f"{key}.txt").write_text(f"# name: {title}\n# source: {url}\n# downloaded: {stamp}\n{body}")
            report.append(f"{key}: {count:,} entries saved")
            break
        else:
            report.append(f"{key}: failed ({'; '.join(errors)})")
    return report
