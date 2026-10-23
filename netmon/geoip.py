"""Country lookup for IP addresses (GeoIP), from the free DB-IP "IP to Country Lite" database.

`python3 -m netmon update-geoip` downloads the current month's file (about 5 MB compressed) into geoip/.
The data is by DB-IP (https://db-ip.com) under the Creative Commons Attribution 4.0 licence.

The file is a CSV of ranges: start address, end address, two-letter country code. Ranges are kept sorted as
integers and looked up with a binary search, so a lookup is fast even with hundreds of thousands of ranges.
"""

from __future__ import annotations

import bisect
import csv
import gzip
import io
import ipaddress
import urllib.request
from datetime import date
from pathlib import Path

URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
ATTRIBUTION = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0"


class GeoIP:
    def __init__(self):
        self.starts = {4: [], 6: []}
        self.ends = {4: [], 6: []}
        self.codes = {4: [], 6: []}
        self.source = None
        self._cache: dict[str, str | None] = {}

    @property
    def size(self) -> int:
        return len(self.starts[4]) + len(self.starts[6])

    def load_rows(self, rows) -> int:
        items = {4: [], 6: []}
        for row in rows:
            if len(row) < 3:
                continue
            try:
                start, end = ipaddress.ip_address(row[0].strip()), ipaddress.ip_address(row[1].strip())
            except ValueError:
                continue
            code = row[2].strip().upper()
            if start.version == end.version and len(code) == 2 and code != "ZZ":
                items[start.version].append((int(start), int(end), code))
        for v in (4, 6):
            merged = sorted(items[v] + list(zip(self.starts[v], self.ends[v], self.codes[v])))
            self.starts[v] = [a for a, _, _ in merged]
            self.ends[v] = [b for _, b, _ in merged]
            self.codes[v] = [c for _, _, c in merged]
        self._cache.clear()
        return len(items[4]) + len(items[6])

    def load_file(self, path: str | Path) -> "GeoIP":
        path = Path(path)
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
            self.load_rows(csv.reader(f))
        self.source = path.name
        return self

    def load_dir(self, folder: str | Path) -> "GeoIP":
        folder = Path(folder)
        files = sorted(folder.glob("*.csv.gz")) + sorted(folder.glob("*.csv")) if folder.is_dir() else []
        if files:
            self.load_file(files[-1])  # the newest download
        return self

    def country(self, ip: str) -> str | None:
        if ip in self._cache:
            return self._cache[ip]
        found = None
        try:
            addr = ipaddress.ip_address(ip)
            v, n = addr.version, int(addr)
            i = bisect.bisect_right(self.starts[v], n) - 1
            if i >= 0 and n <= self.ends[v][i]:
                found = self.codes[v][i]
        except ValueError:
            pass
        if len(self._cache) > 100_000:
            self._cache.clear()
        self._cache[ip] = found
        return found

    def summary(self) -> dict:
        return {"ranges": self.size, "source": self.source, "attribution": ATTRIBUTION if self.size else None}


def update_geoip(folder: str | Path = "geoip", today: date | None = None, timeout: float = 120) -> str:
    """Download this month's database (or last month's if this month's is not out yet)."""
    import ssl

    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    today = today or date.today()
    last_month = date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1)
    errors = []
    for month in (today.strftime("%Y-%m"), last_month.strftime("%Y-%m")):
        url = URL.format(month=month)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netmon (network traffic monitor)"})
            with urllib.request.urlopen(req, timeout=timeout, context=context) as res:
                data = res.read()
            rows = csv.reader(io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(data)), encoding="utf-8"))
            count = GeoIP().load_rows(rows)
            if not count:
                errors.append(f"{month}: no ranges in the file")
                continue
            target = folder / f"dbip-country-lite-{month}.csv.gz"
            target.write_bytes(data)
            for old in folder.glob("dbip-country-lite-*.csv.gz"):
                if old != target:
                    old.unlink()
            return f"geoip: {count:,} ranges saved ({target.name}). {ATTRIBUTION}."
        except Exception as exc:
            errors.append(f"{month}: {type(exc).__name__}: {exc}")
    return "geoip: failed (" + "; ".join(errors) + ")"
