"""Notifications: tell you about serious alerts even when the dashboard is not open.

Channels (use any combination):
  mac       a macOS notification pop-up (uses the built-in osascript command)
  discord   a message to a Discord channel through a webhook URL
  slack     a message to a Slack channel through an incoming-webhook URL
  webhook   the alert as JSON, POSTed to any URL (for your own scripts or tools)
  email     an email through an SMTP server (settings from NETMON_SMTP_* environment variables)

Only alerts at or above the chosen severity (default: high) are sent. To avoid floods, the same alert type from
the same device is sent at most once every 5 minutes, and no more than 10 notifications go out per minute.
Sending happens on a background thread so a slow network never holds up packet processing.
"""

from __future__ import annotations

import json
import os
import platform
import queue
import smtplib
import subprocess
import threading
import time
import urllib.request
from collections import deque
from dataclasses import asdict
from email.message import EmailMessage

from .analyzer import SEVERITY_ORDER


def _text(alert) -> str:
    mitre = ", ".join(m["id"] for m in alert.mitre)
    return f"[{alert.severity.upper()}] {alert.kind}: {alert.message}" + (f" (MITRE {mitre})" if mitre else "")


def _post_json(url: str, payload: dict, timeout: float = 10):
    import ssl

    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "netmon"})
    with urllib.request.urlopen(req, timeout=timeout, context=context if url.startswith("https") else None) as res:
        res.read()


class MacChannel:
    name = "mac"

    def available(self) -> bool:
        return platform.system() == "Darwin"

    def send(self, alert):
        def q(s):  # AppleScript string literal
            return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

        script = (f"display notification {q(alert.message[:200])} with title {q('Network monitor')} "
                  f"subtitle {q(alert.severity.upper() + ' - ' + alert.kind)}")
        subprocess.run(["osascript", "-e", script], check=True, timeout=10, capture_output=True)


class DiscordChannel:
    name = "discord"

    def __init__(self, url):
        self.url = url

    def send(self, alert):
        _post_json(self.url, {"content": _text(alert)[:1900], "username": "Network monitor"})


class SlackChannel:
    name = "slack"

    def __init__(self, url):
        self.url = url

    def send(self, alert):
        _post_json(self.url, {"text": _text(alert)})


class WebhookChannel:
    name = "webhook"

    def __init__(self, url):
        self.url = url

    def send(self, alert):
        _post_json(self.url, {"source": "netmon", "alert": asdict(alert)})


class EmailChannel:
    name = "email"

    def __init__(self, to: str):
        self.to = to
        self.host = os.environ.get("NETMON_SMTP_HOST", "")
        self.port = int(os.environ.get("NETMON_SMTP_PORT", "587"))
        self.user = os.environ.get("NETMON_SMTP_USER", "")
        self.password = os.environ.get("NETMON_SMTP_PASSWORD", "")
        self.sender = os.environ.get("NETMON_SMTP_FROM", self.user or "netmon@localhost")

    def send(self, alert):
        if not self.host:
            raise RuntimeError("NETMON_SMTP_HOST is not set")
        msg = EmailMessage()
        msg["Subject"] = f"[Network monitor] {alert.severity.upper()} {alert.kind}"
        msg["From"], msg["To"] = self.sender, self.to
        msg.set_content(_text(alert) + "\n\nOpen the dashboard for details.")
        with smtplib.SMTP(self.host, self.port, timeout=20) as smtp:
            smtp.starttls()
            if self.user:
                smtp.login(self.user, self.password)
            smtp.send_message(msg)


class Notifier:
    def __init__(self, channels: list, min_severity: str = "high", per_alert_cooldown: float = 300,
                 max_per_minute: int = 10, background: bool = True):
        self.channels = channels
        self.min_severity = min_severity
        self.per_alert_cooldown = per_alert_cooldown
        self.max_per_minute = max_per_minute
        self.sent = 0
        self.suppressed = 0
        self.errors: deque = deque(maxlen=10)
        self._last: dict = {}
        self._recent: deque = deque()
        self._lock = threading.Lock()
        self._queue: queue.Queue | None = None
        if background and channels:
            self._queue = queue.Queue(maxsize=200)
            threading.Thread(target=self._worker, daemon=True, name="notifier").start()

    def wants(self, alert) -> bool:
        return SEVERITY_ORDER.get(alert.severity, 9) <= SEVERITY_ORDER.get(self.min_severity, 0)

    def __call__(self, alert):
        """Analyzer listener: queue the alert if it should be sent."""
        if not self.channels or not self.wants(alert):
            return
        now = time.time()
        with self._lock:
            key = (alert.kind, alert.source)
            while self._recent and now - self._recent[0] > 60:
                self._recent.popleft()
            if now - self._last.get(key, -1e9) < self.per_alert_cooldown or len(self._recent) >= self.max_per_minute:
                self.suppressed += 1
                return
            self._last[key] = now
            self._recent.append(now)
        if self._queue is not None:
            try:
                self._queue.put_nowait(alert)
            except queue.Full:
                self.suppressed += 1
        else:
            self._deliver(alert)

    def _worker(self):
        while True:
            self._deliver(self._queue.get())

    def _deliver(self, alert):
        for channel in self.channels:
            try:
                channel.send(alert)
                with self._lock:
                    self.sent += 1
            except Exception as exc:
                self.errors.append(f"{channel.name}: {type(exc).__name__}: {str(exc)[:120]}")

    def test(self):
        """Send a test notification on every channel (from the dashboard's settings)."""
        from .analyzer import Alert

        alert = Alert(time.time(), "high", "Test", "netmon", "you",
                      "This is a test notification from your network monitor.")
        self._deliver(alert)
        return self.status()

    def status(self) -> dict:
        return {"channels": [c.name for c in self.channels], "min_severity": self.min_severity,
                "sent": self.sent, "suppressed": self.suppressed, "errors": list(self.errors)}


def build_notifier(spec: dict) -> Notifier:
    """spec keys: mac (bool), discord, slack, webhook (URLs), email (address), min_severity."""
    channels = []
    if spec.get("mac"):
        channels.append(MacChannel())
    for key, cls in (("discord", DiscordChannel), ("slack", SlackChannel), ("webhook", WebhookChannel)):
        if spec.get(key):
            channels.append(cls(spec[key]))
    if spec.get("email"):
        channels.append(EmailChannel(spec["email"]))
    return Notifier(channels, min_severity=spec.get("min_severity") or "high")
