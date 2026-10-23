"""Tests for the dashboard API, history database, notifications, responder, PDF report and MCP server."""

import io
import json
import threading
import time
from pathlib import Path

import pytest

from netmon.analyzer import Alert, Analyzer, PacketInfo
from netmon.capture import read_pcap
from netmon.monitor import Monitor
from netmon.notify import Notifier
from netmon.store import AlertStore
from netmon.threatintel import ThreatIntel
from netmon.web import create_app

ROOT = Path(__file__).resolve().parent.parent
DEMO = str(ROOT / "samples" / "demo.pcap")
T0 = 1_792_000_000.0
H = {"X-Netmon": "1"}


class FakeChannel:
    name = "fake"

    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send(self, alert):
        if self.fail:
            raise ConnectionError("down")
        self.sent.append(alert)


@pytest.fixture
def monitor(tmp_path, monkeypatch):
    monkeypatch.setenv("NETMON_PROVIDER", "offline")
    channel = FakeChannel()
    m = Monitor("file: demo", intel=ThreatIntel().load_dir(ROOT / "intel"), ml_learn=None,
                store=AlertStore(tmp_path / "test.db"), notifier=Notifier([channel], background=False))
    m.channel = channel
    read_pcap(m.analyzer, DEMO)
    return m


@pytest.fixture
def client(monitor):
    return create_app(monitor=monitor).test_client()


# ---------------------------------------------------------------- security of the local dashboard

def test_dashboard_rejects_other_hosts_and_cross_site_posts(client):
    assert client.get("/api/snapshot").status_code == 200
    assert client.get("/api/snapshot", headers={"Host": "evil.example"}).status_code == 403  # DNS rebinding
    assert client.post("/api/config", json={"port_scan_ports": 3}).status_code == 403  # no X-Netmon header
    assert client.post("/api/config", json={"port_scan_ports": 3}, headers=H).status_code == 200


# ---------------------------------------------------------------- history and acknowledgement

def test_alerts_are_saved_and_acknowledged(monitor, client):
    stats = monitor.store.stats()
    assert stats["alerts"] == len(monitor.analyzer.alerts) and stats["sessions"] == 1 and stats["open_high"] >= 3
    alert = next(a for a in monitor.analyzer.alerts if a.kind == "Port scan")
    assert client.post(f"/api/alerts/{alert.id}/ack", json={"note": "my own nmap test"}, headers=H).status_code == 200
    assert client.post("/api/alerts/nope/ack", json={}, headers=H).status_code == 404
    history = client.get("/api/history?kind=Port%20scan").get_json()
    assert history["alerts"][0]["acked"] and history["alerts"][0]["ack_note"] == "my own nmap test"
    assert all(not a["acked"] for a in client.get("/api/history?open=1").get_json()["alerts"])
    assert client.get("/api/history?q=cdn-sync").get_json()["alerts"]
    snap = client.get("/api/snapshot").get_json()
    assert next(a for a in snap["alerts"] if a["id"] == alert.id)["acked"]


def test_history_survives_restart(tmp_path):
    db = tmp_path / "h.db"
    store = AlertStore(db)
    a = Analyzer()
    session = store.start_session("first run")
    a.listeners.append(lambda alert: store.add(alert, session))
    a.process(PacketInfo(T0, "192.168.1.99", "192.168.1.1", "TCP", 60, 1, 23, "S"))
    store.close()
    again = AlertStore(db)
    rows = again.history()
    assert len(rows) == 1 and rows[0]["kind"] == "Risky port" and rows[0]["session_source"] == "first run"


# ---------------------------------------------------------------- export, settings, upload

def test_export_csv_and_json(client):
    text = client.get("/api/export/alerts.csv").get_data(as_text=True)
    assert text.splitlines()[0].startswith("id,time,severity,kind") and "T1046" in text
    data = json.loads(client.get("/api/export/alerts.json").get_data())
    assert {"Port scan", "ARP spoofing", "Brute force", "Beaconing"} <= {a["kind"] for a in data}


def test_csv_export_blocks_formula_injection(tmp_path):
    a = Analyzer()
    a.alerts.append(Alert(T0, "low", "Test", "=HYPERLINK(\"http://evil\")", "x", "-1+2"))
    text = create_app(a, "t").test_client().get("/api/export/alerts.csv").get_data(as_text=True)
    assert "'=HYPERLINK" in text and "'-1+2" in text


def test_settings_change_live(client):
    r = client.post("/api/config", json={"brute_force_attempts": 5, "watch_countries": "kp", "bogus": 1}, headers=H)
    assert r.status_code == 400 and r.get_json()["errors"] == {"bogus": "unknown setting"}
    config = client.get("/api/config").get_json()
    assert config["brute_force_attempts"] == 5 and config["watch_countries"] == "KP"


def test_upload_starts_a_new_session(monitor, client):
    assert client.post("/api/upload", data={"file": (io.BytesIO(b"x"), "notes.txt")}, headers=H,
                       content_type="multipart/form-data").status_code == 400
    data = {"file": (io.BytesIO(Path(DEMO).read_bytes()), "office.pcap")}
    r = client.post("/api/upload", data=data, headers=H, content_type="multipart/form-data")
    assert r.status_code == 200 and r.get_json()["source"] == "upload: office.pcap"
    for _ in range(100):
        if not monitor.busy:
            break
        time.sleep(0.1)
    snap = client.get("/api/snapshot").get_json()
    assert snap["packets"] == 6260 and snap["status"]["source"] == "upload: office.pcap"
    assert monitor.store.stats()["sessions"] == 2


# ---------------------------------------------------------------- notifications

def test_notifications_only_for_serious_alerts_and_rate_limited(monitor):
    kinds = [a.kind for a in monitor.channel.sent]
    assert kinds and all(a.severity == "high" for a in monitor.channel.sent)
    assert "Risky port" not in kinds  # medium: below the default minimum
    assert len(kinds) == len(set((a.kind, a.source) for a in monitor.channel.sent))  # no repeats
    assert monitor.notifier.status()["sent"] == len(kinds)


def test_notifier_limits_and_errors():
    channel = FakeChannel()
    n = Notifier([channel], min_severity="medium", max_per_minute=3, background=False)
    for i in range(6):
        n(Alert(T0, "medium", "Risky port", f"192.168.1.{i}", "x", "m"))
    assert len(channel.sent) == 3 and n.suppressed == 3
    broken = Notifier([FakeChannel(fail=True)], background=False)
    broken(Alert(T0, "high", "Port scan", "a", "b", "m"))
    assert broken.status()["errors"][0].startswith("fake: ConnectionError")


def test_mac_channel_escapes_quotes(monkeypatch):
    from netmon import notify

    calls = []
    monkeypatch.setattr(notify.subprocess, "run", lambda args, **kw: calls.append(args))
    notify.MacChannel().send(Alert(T0, "high", "Threat intel", "a", "b", 'looked up "evil" \\ domain'))
    script = calls[0][2]
    assert 'looked up \\"evil\\" \\\\ domain' in script and "HIGH - Threat intel" in script


# ---------------------------------------------------------------- responder

def test_responder_proposes_and_requires_approval(monitor, client):
    actions = client.get("/api/responses").get_json()["responses"]
    titles = {a["title"] for a in actions}
    assert {"Isolate device 192.168.1.99", "Block domain cdn-sync.example",
            "Block outside server 203.0.113.50", "Close port 23 on 192.168.1.1"} <= titles
    assert all(a["status"] == "proposed" for a in actions)
    assert "No actions approved yet" in client.get("/api/responses/script?platform=pf").get_data(as_text=True)
    target = next(a for a in actions if a["title"] == "Isolate device 192.168.1.99")
    assert client.post(f"/api/responses/{target['id']}", json={"status": "approved"}, headers=H).status_code == 200
    assert client.post(f"/api/responses/{target['id']}", json={"status": "run-it"}, headers=H).status_code == 400
    pf = client.get("/api/responses/script?platform=pf").get_data(as_text=True)
    assert "block drop quick from 192.168.1.99 to any" in pf and "REVIEW EVERY LINE" in pf
    ps = client.get("/api/responses/script?platform=powershell").get_data(as_text=True)
    assert "New-NetFirewallRule" in ps and "192.168.1.99" in ps
    assert client.get("/api/responses/script?platform=bash").status_code == 400


def test_agent_can_see_responses(client):
    out = client.post("/api/tools/get_proposed_responses", json={}, headers=H).get_json()
    assert out["responses"] and "Nothing is applied automatically" in out["note"]


# ---------------------------------------------------------------- PDF report

def test_pdf_report(client):
    r = client.get("/api/report.pdf")
    assert r.status_code == 200 and r.mimetype == "application/pdf" and r.data[:5] == b"%PDF-"
    assert len(r.data) > 5000


# ---------------------------------------------------------------- MCP server

def test_mcp_server_over_stdio(monitor):
    from werkzeug.serving import make_server

    from netmon.mcp_server import MCPServer

    server = make_server("127.0.0.1", 0, create_app(monitor=monitor), threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        out = io.StringIO()
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "list_alerts", "arguments": {"severity": "high"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "rm_rf", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 5, "method": "nope"},
        ]
        MCPServer(f"http://127.0.0.1:{server.server_port}", out=out).serve(
            io.StringIO("\n".join(json.dumps(r) for r in requests) + "\nnot json\n"))
        replies = [json.loads(line) for line in out.getvalue().splitlines()]
    finally:
        server.shutdown()
    assert [r.get("id") for r in replies] == [1, 2, 3, 4, 5, None]  # no reply to the notification
    assert replies[0]["result"]["serverInfo"]["name"] == "network-traffic-monitor"
    assert "get_proposed_responses" in {t["name"] for t in replies[1]["result"]["tools"]}
    alerts = json.loads(replies[2]["result"]["content"][0]["text"])["alerts"]
    assert alerts and all(a["severity"] == "high" for a in alerts)
    assert replies[3]["error"]["code"] == -32602 and replies[4]["error"]["code"] == -32601
    assert replies[5]["error"]["code"] == -32700


def test_mcp_server_reports_when_dashboard_is_down():
    from netmon.mcp_server import MCPServer

    out = MCPServer("http://127.0.0.1:9").call_tool("get_overview", {})
    assert "cannot reach the network monitor" in out["error"]
