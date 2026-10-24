"""Alert history in a SQLite database, so alerts survive restarts and can be searched later.

Every run of the monitor is a "session". Each alert is saved the moment it is raised, together with the
session it belongs to. Marking an alert as handled on the dashboard is saved too.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, started REAL NOT NULL, source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, session TEXT NOT NULL REFERENCES sessions(id), ts REAL NOT NULL,
    severity TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL,
    message TEXT NOT NULL, mitre TEXT NOT NULL DEFAULT '[]',
    acked INTEGER NOT NULL DEFAULT 0, ack_note TEXT NOT NULL DEFAULT '', acked_at REAL
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS alerts_kind ON alerts(kind);
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, ip TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL, last_seen REAL NOT NULL
);
"""


class AlertStore:
    def __init__(self, path: str | Path = "netmon.db"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)
            self.db.commit()

    def start_session(self, source: str) -> str:
        session = uuid.uuid4().hex[:12]
        with self.lock:
            self.db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (session, time.time(), source))
            self.db.commit()
        return session

    def add(self, alert, session: str):
        a = asdict(alert)
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO alerts (id, session, ts, severity, kind, source, target, message, mitre, "
                "acked, ack_note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (a["id"], session, a["ts"], a["severity"], a["kind"], a["source"], a["target"], a["message"],
                 json.dumps(a["mitre"]), int(a["acked"]), a["ack_note"]))
            self.db.commit()

    def acknowledge(self, alert_id: str, note: str = "", acked: bool = True) -> bool:
        with self.lock:
            cur = self.db.execute("UPDATE alerts SET acked = ?, ack_note = ?, acked_at = ? WHERE id = ?",
                                  (int(acked), note[:500], time.time() if acked else None, alert_id))
            self.db.commit()
            return cur.rowcount > 0

    def history(self, limit: int = 200, severity: str | None = None, kind: str | None = None,
                query: str | None = None, include_acked: bool = True, session: str | None = None) -> list[dict]:
        sql = ("SELECT alerts.*, sessions.source AS session_source FROM alerts "
               "JOIN sessions ON sessions.id = alerts.session WHERE 1=1")
        args: list = []
        if severity:
            sql += " AND alerts.severity = ?"
            args.append(severity)
        if kind:
            sql += " AND alerts.kind = ?"
            args.append(kind)
        if session:
            sql += " AND alerts.session = ?"
            args.append(session)
        if not include_acked:
            sql += " AND alerts.acked = 0"
        if query:
            sql += " AND (alerts.message LIKE ? OR alerts.source LIKE ? OR alerts.target LIKE ?)"
            args += [f"%{query}%"] * 3
        sql += " ORDER BY alerts.ts DESC LIMIT ?"
        args.append(max(1, min(int(limit), 5000)))
        with self.lock:
            rows = self.db.execute(sql, args).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["mitre"] = json.loads(item["mitre"])
            item["acked"] = bool(item["acked"])
            out.append(item)
        return out

    def stats(self) -> dict:
        with self.lock:
            total = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            sessions = self.db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            by_kind = dict(self.db.execute(
                "SELECT kind, COUNT(*) FROM alerts GROUP BY kind ORDER BY COUNT(*) DESC").fetchall())
            open_high = self.db.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = 'high' AND acked = 0").fetchone()[0]
        return {"path": self.path, "alerts": total, "sessions": sessions, "by_kind": by_kind,
                "open_high": open_high}

    # ------------------------------------------------------------------ remembered devices

    def known_devices(self) -> dict:
        """Every device seen in earlier runs, by hardware (MAC) address."""
        with self.lock:
            rows = self.db.execute("SELECT * FROM devices").fetchall()
        return {row["mac"]: dict(row) for row in rows}

    def save_devices(self, devices: list[dict]):
        """Insert or update devices; keeps the name you gave each one and when it was first seen."""
        with self.lock:
            for d in devices:
                self.db.execute(
                    "INSERT INTO devices (mac, ip, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, last_seen = MAX(last_seen, excluded.last_seen), "
                    "hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END, "
                    "first_seen = MIN(first_seen, excluded.first_seen)",
                    (d["mac"].lower(), d["ip"], d.get("hostname") or "", d["first_seen"], d["last_seen"]))
            self.db.commit()

    def set_label(self, mac: str, label: str) -> bool:
        with self.lock:
            cur = self.db.execute("UPDATE devices SET label = ? WHERE mac = ?", (label.strip()[:60], mac.lower()))
            self.db.commit()
            return cur.rowcount > 0

    def close(self):
        with self.lock:
            self.db.close()
