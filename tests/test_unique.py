"""Tests for the Privacy X-ray, encrypted-traffic (JA4) detection, the self-test and the attack story."""

import json
from pathlib import Path

import pytest

from netmon.analyzer import Analyzer, Config, PacketInfo
from netmon.capture import read_pcap
from netmon.payload import (TLSReassembler, build_client_hello, dhcp_hostname, dns_answers,
                            parse_client_hello)
from netmon.privacy import PrivacyTracker, classify, load_disconnect
from netmon.threatintel import ThreatIntel

ROOT = Path(__file__).resolve().parent.parent
DEMO = str(ROOT / "samples" / "demo.pcap")
T0 = 1_792_000_000.0


@pytest.fixture(scope="module")
def demo():
    a = Analyzer(intel=ThreatIntel().load_dir(ROOT / "intel"))
    read_pcap(a, DEMO)
    return a


# ---------------------------------------------------------------- payload parsing

def test_ja4_matches_the_published_example():
    # The JA4 specification's example Chrome hello: t13d1516h2_8daaf6152771_e5627efa2ab1
    hello = parse_client_hello(build_client_hello("www.example.com"))
    assert hello == {"sni": "www.example.com", "alpn": "h2", "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"}
    assert parse_client_hello(build_client_hello(None, alpn=()))["ja4"].startswith("t13i151500_")
    assert parse_client_hello(b"\x16\x03\x01\x00\x10\x01") is None  # cut off
    assert parse_client_hello(b"GET / HTTP/1.1\r\n") is None


def test_hello_split_over_two_packets_is_joined():
    big = build_client_hello("split.example", padding=1500)  # bigger than one packet, like post-quantum hellos
    tls, flow = TLSReassembler(), ("10.0.0.2", 5000, "198.51.100.1", 443)
    assert tls.feed(flow, big[:1400]) is None
    assert tls.feed(flow, big[1400:])["sni"] == "split.example"
    assert not tls.pending


def test_dns_answers_follow_cname_chains_and_dhcp_names():
    from scapy.all import BOOTP, DHCP, DNS, DNSQR, DNSRR, raw

    reply = DNS(id=1, qr=1, qd=DNSQR(qname="metrics.shop.example"),
                an=[DNSRR(rrname="metrics.shop.example", type="CNAME", rdata="a.cdn.example"),
                    DNSRR(rrname="a.cdn.example", type="CNAME", rdata="shop.eulerian.net"),
                    DNSRR(rrname="shop.eulerian.net", type="A", rdata="203.0.113.9")])
    assert dns_answers(raw(reply)) == [("metrics.shop.example", "203.0.113.9", "shop.eulerian.net")]
    assert dns_answers(raw(DNS(id=1, qr=0, qd=DNSQR(qname="x.example")))) == []  # a question, not a reply
    assert dns_answers(b"\x00\x01") == []
    request = BOOTP(chaddr=b"\x01" * 6) / DHCP(options=[("message-type", "request"), ("hostname", b"Lounge-TV"), "end"])
    assert dhcp_hostname(raw(request)) == "Lounge-TV"


def test_both_readers_extract_the_same_details():
    from scapy.all import PcapReader

    from netmon.capture import iter_pcap_fast, to_packet_info

    fast = list(iter_pcap_fast(DEMO))
    tls = TLSReassembler()
    slow = [x for x in (to_packet_info(p, tls) for p in PcapReader(DEMO)) if x]
    assert fast == slow
    assert sum(1 for p in fast if p.tls_sni) > 100 and sum(1 for p in fast if p.dns_answers) > 100
    assert any(p.hostname == "Nikhils-iPhone" for p in fast)


# ---------------------------------------------------------------- privacy x-ray

def test_classify_prefers_the_longest_match():
    assert classify("ads.linkedin.com") == ("LinkedIn", "advertising")
    assert classify("www.linkedin.com") == ("LinkedIn", "social")
    assert classify("log-config.samsungacr.com.") == ("Samsung", "tv-tracking")
    assert classify("shop.example.co.uk") == ("example.co.uk", "service")


def test_privacy_report_on_demo(demo):
    report = demo.privacy.report()
    by_device = {d["device"]: d for d in report["devices"]}
    assert by_device["192.168.1.12"]["kind"] == "Smart TV"
    assert by_device["192.168.1.11"]["hostname"] == "Nikhils-iPhone"
    texts = [f["text"] for f in report["findings"]]
    assert texts[0].startswith("Smart TV (192.168.1.12) sent") and "TV viewing tracking" in texts[0]
    cloaked = [f for f in report["findings"] if "CNAME cloaking" in f["text"]]
    assert cloaked and cloaked[0]["severity"] == "high" and "shopnow.eulerian.net" in cloaked[0]["text"]
    assert {r["company"] for r in by_device["192.168.1.11"]["parties"]} >= {"Meta", "Google (Firebase)"}
    json.dumps(report)


def test_disconnect_list_is_read(tmp_path):
    path = tmp_path / "services.json"
    path.write_text(json.dumps({"license": "test", "categories": {
        "Advertising": [{"AdCo": {"https://adco.example/": ["adco.example", "adco-cdn.example"]}}],
        "Content": [{"VideoCo": {"https://video.example/": ["video.example"]}}],
        "Email": [{"MailPix": {"https://mailpix.example/": ["mailpix.example"]}}]}}))
    extra = load_disconnect(path)
    assert extra == {"adco.example": ("AdCo", "advertising"), "adco-cdn.example": ("AdCo", "advertising"),
                     "mailpix.example": ("MailPix", "analytics")}
    tracker = PrivacyTracker(extra=extra)
    tracker.observe(PacketInfo(T0, "192.168.1.5", "198.51.100.7", "TCP", 900, 5000, 443, "PA", tls_sni="x.adco.example"))
    assert tracker.report()["devices"][0]["parties"][0]["company"] == "AdCo"


# ---------------------------------------------------------------- encrypted traffic

NORMAL = parse_client_hello(build_client_hello("www.example.com"))["ja4"]
ODD = parse_client_hello(build_client_hello(None, ciphers=[0xC02F], extensions=[0x000A], alpn=()))["ja4"]


def _tls(t, ja4, sni=None, dst="198.51.100.9"):
    return PacketInfo(T0 + t, "192.168.1.20", dst, "TCP", 600, 40000 + int(t), 443, "PA", tls_sni=sni, ja4=ja4)


def test_unusual_tls_client_after_learning_only():
    a = Analyzer()
    a.process(_tls(0, NORMAL, "www.example.com"))
    a.process(_tls(10, ODD))  # still learning: no alert
    a.process(_tls(70, parse_client_hello(build_client_hello("x.example", ciphers=[0x1301]))["ja4"], "x.example"))
    assert not [x for x in a.alerts if x.kind == "Unusual TLS client"]  # new program, but it named the site
    third = parse_client_hello(build_client_hello(None, ciphers=[0x002F, 0x0035], alpn=()))["ja4"]
    a.process(_tls(80, third))
    alerts = [x for x in a.alerts if x.kind == "Unusual TLS client"]
    assert len(alerts) == 1 and third in alerts[0].message and alerts[0].mitre[0]["id"] == "T1573"
    a.process(_tls(200, third))  # the same program again is no longer new
    assert len([x for x in a.alerts if x.kind == "Unusual TLS client"]) == 1
    programs = {x["ja4"]: x["connections"] for x in a.host_detail("192.168.1.20")["tls_programs"]}
    assert programs[NORMAL] == 1 and programs[third] == 2


def test_ja4_blocklist():
    intel = ThreatIntel()
    assert intel.load_text(f"# name: Bad tools\n{ODD}\n", "x") == 1
    a = Analyzer(intel=intel)
    a.process(_tls(0, ODD))
    alert = [x for x in a.alerts if x.kind == "Threat intel"][0]
    assert alert.severity == "high" and "Bad tools" in alert.message and ODD in alert.message


# ---------------------------------------------------------------- self-test

def test_self_test_passes_with_defaults_and_flags_bad_settings():
    from netmon.selftest import run_drills

    result = run_drills(Config())
    assert result["ok"] and result["passed"] == result["total"] == 9
    loose = Config()
    loose.update({"port_scan_ports": 5000, "brute_force_attempts": 500})
    missed = {r["drill"]: r["fix"] for r in run_drills(loose)["results"] if not r["ok"]}
    assert set(missed) == {"Port scan", "Password guessing"} and "port_scan_ports" in missed["Port scan"]
    intel = ThreatIntel()
    intel.load_text("198.51.100.77\n", "List")
    assert run_drills(Config(), intel)["total"] == 10


def test_self_test_never_touches_the_real_alerts(tmp_path):
    from netmon.monitor import Monitor

    m = Monitor("test", ml_learn=None)
    m.analyzer.config.update({"heavy_bytes": 10 ** 12})
    result = m.run_self_test(raise_alert=True)
    assert not result["ok"]
    kinds = [a.kind for a in m.analyzer.alerts]
    assert kinds == ["Self-test"]  # only the warning, none of the drills' attack alerts
    assert "Data theft" in m.analyzer.alerts[0].message
    assert m.status()["self_test"] == {"passed": result["passed"], "total": result["total"], "ok": False}


def test_capture_health():
    from netmon.selftest import capture_health

    a = Analyzer()
    assert capture_health(a, live=True)["state"] == "waiting"
    a.process(PacketInfo(1000.0, "192.168.1.2", "1.1.1.1", "UDP", 60, 1, 2))
    assert capture_health(a, live=True, now=1010)["state"] == "ok"
    assert capture_health(a, live=True, now=1500)["state"] == "stalled"
    assert capture_health(a, live=False)["state"] == "not live"


def test_selftest_cli(capsys):
    from netmon.__main__ import main

    assert main(["selftest", "--intel", str(ROOT / "intel")]) == 0
    assert main(["selftest", "--set", "port_scan_ports=5000"]) == 1
    assert "MISSED" in capsys.readouterr().out


# ---------------------------------------------------------------- attack story

def test_story_on_demo(demo):
    from netmon.story import build

    data = build(demo.snapshot()["alerts"], {m: ip for ip, m in demo.ip_mac.items()})
    titles = [i["title"] for i in data["incidents"]]
    assert titles[0] == "Intruder 192.168.1.99 on the network"
    first = data["incidents"][0]
    assert first["stages"] == ["Initial access", "Reconnaissance", "Credential access"]
    assert "impersonated 192.168.1.1" in first["story"] and "Not seen (yet)" in first["story"]
    assert {"192.168.1.11 may be infected", "192.168.1.12 may be infected"} <= set(titles)


def test_story_joins_an_attack_that_spreads():
    from netmon.story import build

    a = Analyzer()
    for i, port in enumerate(range(1, 25)):  # 192.168.1.66 scans the laptop ...
        a.process(PacketInfo(T0 + i * 0.1, "192.168.1.66", "192.168.1.10", "TCP", 60, 6000, port, "S"))
    for i in range(12):  # ... then the laptop starts calling home
        a.process(PacketInfo(T0 + 100 + i * 30, "192.168.1.10", "198.51.100.23", "TCP", 60, 45000 + i, 443, "S"))
    incidents = build(a.snapshot()["alerts"])["incidents"]
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["actors"] == ["192.168.1.66", "192.168.1.10"]
    assert inc["title"] == "Attack spreading from 192.168.1.66 to 192.168.1.10"
    assert {"Reconnaissance", "Command and control"} <= set(inc["stages"]) and "spread" in inc["story"]


# ---------------------------------------------------------------- dashboard and analyst

def test_new_endpoints_and_tools(monkeypatch):
    monkeypatch.setenv("NETMON_PROVIDER", "offline")
    from netmon.agent import OfflineAnalyst, Toolbox
    from netmon.monitor import Monitor
    from netmon.web import create_app

    m = Monitor("file: demo", intel=ThreatIntel().load_dir(ROOT / "intel"), ml_learn=None)
    read_pcap(m.analyzer, DEMO)
    client = create_app(monitor=m).test_client()
    assert client.get("/api/privacy").get_json()["findings"]
    assert client.get("/api/story").get_json()["incidents"][0]["title"].startswith("Intruder")
    assert client.post("/api/selftest").status_code == 403  # needs the X-Netmon header
    assert client.post("/api/selftest", headers={"X-Netmon": "1"}).get_json()["ok"]
    assert client.get("/api/health").get_json()["self_test"]["passed"] == 10

    tools = Toolbox(m.analyzer)
    assert tools.run("get_attack_story", {})["incidents"][0]["stages_reached"][0] == "Initial access"
    assert tools.run("get_privacy_report", {"device": "192.168.1.12"})["devices"][0]["kind"] == "Smart TV"
    assert tools.run("get_self_test", {})["passed"] == 10
    offline = OfflineAnalyst(m.analyzer)
    assert "samsungacr" in offline.answer("Which companies is my TV sending data to? privacy").report
    assert "## Attack story" in offline.answer("What happened, as a story?").report
