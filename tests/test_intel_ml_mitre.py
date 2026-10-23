"""Tests for MITRE ATT&CK tagging, threat intelligence and machine-learning anomaly detection."""

import json
from pathlib import Path

import pytest

from netmon.analyzer import Analyzer, PacketInfo
from netmon.mitre import techniques_for
from netmon.threatintel import ThreatIntel, update_feeds

ROOT = Path(__file__).resolve().parent.parent
T0 = 1_792_000_000.0


# ---------------------------------------------------------------- MITRE ATT&CK

def test_alerts_carry_mitre_techniques():
    a = Analyzer()
    for i, port in enumerate(range(1, 20)):
        a.process(PacketInfo(T0 + i * 0.1, "192.168.1.99", "192.168.1.10", "TCP", 60, 61000, port, "S"))
    by_kind = {al.kind: al for al in a.alerts}
    scan = by_kind["Port scan"].mitre[0]
    assert scan["id"] == "T1046" and scan["tactic"] == "Discovery"
    assert scan["url"] == "https://attack.mitre.org/techniques/T1046/"
    assert [m["id"] for m in techniques_for("Risky port", 3389)] == ["T1021.001"]
    assert techniques_for("Suspicious DNS")[0]["url"].endswith("/T1071/004/")
    assert techniques_for("Anomaly (ML)") == []


# ---------------------------------------------------------------- threat intelligence

def test_intel_parses_all_feed_formats():
    intel = ThreatIntel()
    intel.load_text("# name: Plain list\n# comment\n198.51.100.7\n198.51.100.0/30 ; note\n", "x")
    intel.load_text('{"cidr":"192.0.2.0/24","sblid":"SBL1"}\n{"type":"metadata","records":1}\n', "Spamhaus")
    intel.load_text("# hosts file\n127.0.0.1 localhost\n127.0.0.1 evil-malware.example\n0.0.0.0 bad.test\n", "URLhaus")
    assert intel.match_ip("198.51.100.7") == "Plain list"
    assert intel.match_ip("198.51.100.2") == "Plain list"  # inside the /30
    assert intel.match_ip("192.0.2.200") == "Spamhaus"
    assert intel.match_ip("8.8.8.8") is None
    assert intel.match_domain("cdn.evil-malware.example.") == ("evil-malware.example", "URLhaus")
    assert intel.match_domain("localhost") is None  # hosts-file housekeeping lines are skipped
    assert intel.summary()["lists"] == {"Plain list": 2, "Spamhaus": 1, "URLhaus": 2}


def test_intel_alerts_on_listed_ip_and_domain():
    intel = ThreatIntel()
    intel.load_text("203.0.113.50\nbad-domain.example\n", "Test list")
    a = Analyzer(intel=intel)
    a.process(PacketInfo(T0, "192.168.1.11", "203.0.113.50", "TCP", 1400, 5000, 443, "S"))
    a.process(PacketInfo(T0 + 1, "203.0.113.50", "192.168.1.11", "TCP", 60, 443, 5000, "SA"))  # reply: same alert
    a.process(PacketInfo(T0 + 2, "192.168.1.12", "192.168.1.1", "DNS", 80, 5, 53, dns_query="x.bad-domain.example."))
    intel_alerts = [al for al in a.alerts if al.kind == "Threat intel"]
    assert len(intel_alerts) == 2
    assert intel_alerts[0].severity == "high" and "Test list" in intel_alerts[0].message
    assert intel_alerts[1].target == "bad-domain.example"
    assert a.snapshot()["intel"]["indicators"] == 2


def test_demo_blocklist_ships_with_project():
    intel = ThreatIntel().load_dir(ROOT / "intel")
    assert intel.match_ip("203.0.113.50") and intel.match_domain("abc.cdn-sync.example")


def test_update_feeds_saves_lists(tmp_path, monkeypatch):
    import netmon.threatintel as ti

    class FakeResponse:
        def __init__(self, body):
            self.body = body.encode()

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    bodies = {"https://a.example/list": "198.51.100.9\n", "https://b.example/empty": "# nothing\n"}

    def fake_urlopen(req, timeout, context=None):
        if req.full_url == "https://c.example/down":
            raise OSError("unreachable")
        return FakeResponse(bodies[req.full_url])

    monkeypatch.setattr(ti.urllib.request, "urlopen", fake_urlopen)
    report = update_feeds(tmp_path, {"good": (["https://c.example/down", "https://a.example/list"], "Good feed"),
                                     "empty": ("https://b.example/empty", "Empty"),
                                     "down": ("https://c.example/down", "Down")})
    assert report[0] == "good: 1 entries saved"  # the first mirror failed, the second worked
    assert "no entries" in report[1] and "failed" in report[1] and "unreachable" in report[2]
    loaded = ThreatIntel().load_dir(tmp_path)
    assert loaded.match_ip("198.51.100.9") == "Good feed"  # the "# name:" header was written


# ---------------------------------------------------------------- machine learning

ml = pytest.importorskip("sklearn")


def _normal(analyzer, start, seconds, devices=("192.168.1.10", "192.168.1.11", "192.168.1.12")):
    for s in range(seconds):
        for i, dev in enumerate(devices):
            t = T0 + start + s + i * 0.1
            analyzer.process(PacketInfo(t, dev, "192.168.1.1", "DNS", 70, 50000 + s, 53, dns_query="github.com."))
            analyzer.process(PacketInfo(t + 0.02, dev, "20.248.137.48", "TCP", 60, 50000 + s, 443, "S"))
            for k in range(3):
                analyzer.process(PacketInfo(t + 0.05 + k * 0.01, dev, "20.248.137.48", "TCP", 54, 50000 + s, 443, "A"))


def test_ml_learns_then_flags_only_unusual_behaviour():
    from netmon.ml import AnomalyDetector

    det = AnomalyDetector(window=5, learn_seconds=40)
    a = Analyzer(ml=det)
    _normal(a, 0, 40)
    assert det.status()["state"] == "learning"
    _normal(a, 40, 40)  # more normal traffic: no anomalies
    assert det.status()["state"] == "active"
    assert not [al for al in a.alerts if al.kind == "Anomaly (ML)"]
    # A device suddenly contacts many ports on many hosts.
    for i in range(60):
        a.process(PacketInfo(T0 + 81 + i * 0.05, "192.168.1.12", f"192.168.1.{100 + i % 30}", "TCP", 60, 6000,
                             1000 + i, "S"))
    a.finish()
    anomalies = [al for al in a.alerts if al.kind == "Anomaly (ML)"]
    assert len(anomalies) == 1 and anomalies[0].source == "192.168.1.12"
    assert "contacted 60 different ports (normal: up to 2)" in anomalies[0].message


def test_ml_on_demo_capture_finds_the_three_bad_devices():
    from netmon.capture import read_pcap
    from netmon.ml import AnomalyDetector

    a = Analyzer(ml=AnomalyDetector())
    read_pcap(a, str(ROOT / "samples" / "demo.pcap"))
    flagged = {al.source for al in a.alerts if al.kind == "Anomaly (ML)"}
    assert flagged == {"192.168.1.99", "192.168.1.11", "192.168.1.12"}  # intruder, upload, DNS leak
    assert "192.168.1.10" not in flagged  # the normal laptop is never flagged
    status = a.snapshot()["ml"]
    assert status["state"] == "active" and status["trained_on"] >= 12


def test_ml_without_sklearn_is_disabled_gracefully(monkeypatch):
    import builtins

    from netmon.ml import AnomalyDetector

    real_import = builtins.__import__

    def no_sklearn(name, *args, **kwargs):
        if name.startswith("sklearn"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_sklearn)
    det = AnomalyDetector()
    assert det.status()["state"] == "unavailable"
    assert det.observe(PacketInfo(T0, "192.168.1.10", "1.1.1.1", "TCP", 60, 1, 2, "S")) == []


def test_agent_sees_mitre_intel_and_ml():
    from netmon.agent import OfflineAnalyst, Toolbox
    from netmon.capture import read_pcap
    from netmon.ml import AnomalyDetector

    a = Analyzer(intel=ThreatIntel().load_dir(ROOT / "intel"), ml=AnomalyDetector())
    read_pcap(a, str(ROOT / "samples" / "demo.pcap"))
    overview = Toolbox(a).run("get_overview", {})
    assert overview["incidents"][0]["type"] == "Threat intel"  # most serious first
    assert overview["machine_learning"]["state"] == "active" and overview["threat_intel"]["indicators"] == 2
    alerts = Toolbox(a).run("list_alerts", {"kind": "Port scan"})["alerts"]
    assert alerts[0]["mitre_attack"] == ["T1046 Network Service Discovery (Discovery)"] and "ts" not in alerts[0]
    report = OfflineAnalyst(a).answer("Investigate").report
    assert "### Threat intel - High" in report and "`T1046` Network Service Discovery" in report
    json.dumps(a.snapshot())  # the dashboard API can serialise everything
