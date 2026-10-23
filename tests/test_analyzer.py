from pathlib import Path

import pytest

from netmon.analyzer import Analyzer, Config, PacketInfo, shannon_entropy

T0 = 1_792_000_000.0


def kinds(alerts):
    return [a.kind for a in alerts]


def run(packets, config=None):
    analyzer = Analyzer(config)
    alerts = []
    for p in packets:
        alerts += analyzer.process(p)
    return analyzer, alerts


def normal_traffic(seconds=60):
    out = []
    for s in range(seconds):
        out.append(PacketInfo(T0 + s, "192.168.1.10", "192.168.1.1", "DNS", 70, 50000 + s, 53, dns_query="github.com."))
        out.append(PacketInfo(T0 + s + 0.1, "192.168.1.10", "20.248.137.48", "TCP", 60, 50000 + s, 443, "S"))
        out.append(PacketInfo(T0 + s + 0.2, "20.248.137.48", "192.168.1.10", "TCP", 1400, 443, 50000 + s, "A"))
    return out


def test_normal_traffic_raises_no_alerts():
    analyzer, alerts = run(normal_traffic())
    assert alerts == []
    snap = analyzer.snapshot()
    assert snap["packets"] == 180
    assert snap["protocols"] == {"DNS": 60, "TCP": 120}
    assert snap["dns"][0] == {"domain": "github.com", "count": 60}


def test_port_scan_detected_once():
    scan = [PacketInfo(T0 + i * 0.1, "192.168.1.99", "192.168.1.10", "TCP", 60, 61000, port, "S")
            for i, port in enumerate(range(1, 60))]
    _, alerts = run(scan)
    scans = [a for a in alerts if a.kind == "Port scan"]
    assert len(scans) == 1  # repeated alerts are suppressed by the cooldown
    assert scans[0].severity == "high"
    assert "15 different ports" in scans[0].message
    assert kinds(alerts).count("Risky port") == 2  # the scan also hit FTP (21) and Telnet (23)


def test_slow_connections_are_not_a_scan():
    slow = [PacketInfo(T0 + i * 5, "192.168.1.99", "192.168.1.10", "TCP", 60, 61000, port, "S")
            for i, port in enumerate(range(1, 40))]
    _, alerts = run(slow)
    assert "Port scan" not in kinds(alerts)


def test_syn_ack_replies_do_not_count_as_scanning():
    replies = [PacketInfo(T0 + i * 0.01, "192.168.1.10", "192.168.1.99", "TCP", 60, port, 61000, "SA")
               for i, port in enumerate(range(1, 60))]
    _, alerts = run(replies)
    assert alerts == []


def test_risky_port():
    _, alerts = run([PacketInfo(T0, "192.168.1.99", "192.168.1.1", "TCP", 60, 61001, 23, "S")])
    assert kinds(alerts) == ["Risky port"]
    assert "Telnet" in alerts[0].message


def test_syn_flood():
    flood = [PacketInfo(T0 + i * 0.01, f"10.0.{i % 250}.{i % 200 + 1}", "192.168.1.10", "TCP", 60, 1000 + i, 80, "S")
             for i in range(300)]
    _, alerts = run(flood)
    assert "SYN flood" in kinds(alerts)


def test_dns_tunnelling():
    random_label = "q8z3kd92mfp0xv7ls1ty6wre4nbc5hgj0aui2o"
    _, alerts = run([PacketInfo(T0, "192.168.1.12", "192.168.1.1", "DNS", 120, 50000, 53,
                                dns_query=f"{random_label}.cdn-sync.example.")])
    assert kinds(alerts) == ["Suspicious DNS"]
    assert alerts[0].target == "cdn-sync.example"


def test_ordinary_long_domain_is_fine():
    _, alerts = run([PacketInfo(T0, "192.168.1.12", "192.168.1.1", "DNS", 90, 50000, 53,
                                dns_query="clientservices.googleapis.com.")])
    assert alerts == []


def test_heavy_upload():
    upload = [PacketInfo(T0 + i * 0.002, "192.168.1.11", "203.0.113.50", "TCP", 1454, 52000, 443, "A")
              for i in range(4000)]
    _, alerts = run(upload)
    assert kinds(alerts) == ["High traffic"]
    assert alerts[0].source == "192.168.1.11"
    assert "mostly to 203.0.113.50 (outside your network)" in alerts[0].message


def test_new_device_only_after_warmup():
    packets = [PacketInfo(T0, "192.168.1.10", "192.168.1.1", "TCP", 60, 1, 2),
               PacketInfo(T0 + 10, "192.168.1.11", "192.168.1.1", "TCP", 60, 1, 2),
               PacketInfo(T0 + 45, "192.168.1.99", "192.168.1.1", "TCP", 60, 1, 2, src_mac="de:ad:be:ef:00:99")]
    analyzer, alerts = run(packets)
    assert kinds(alerts) == ["New device"]
    assert "192.168.1.99" in alerts[0].message and "de:ad:be:ef:00:99" in alerts[0].message
    assert [d["ip"] for d in analyzer.snapshot()["devices"]] == ["192.168.1.10", "192.168.1.11", "192.168.1.99"]


def test_thresholds_are_configurable():
    scan = [PacketInfo(T0 + i * 0.1, "192.168.1.99", "192.168.1.10", "TCP", 60, 61000, port, "S")
            for i, port in enumerate(range(1, 6))]
    _, alerts = run(scan, Config(port_scan_ports=5))
    assert kinds(alerts) == ["Port scan"]


def test_base_domain():
    from netmon.analyzer import base_domain
    assert base_domain("www.uow.edu.au.") == "uow.edu.au"
    assert base_domain("mail.google.com") == "google.com"


def test_is_local():
    from netmon.analyzer import is_local
    assert is_local("192.168.1.10") and is_local("10.1.2.3") and is_local("172.20.0.5")
    assert not is_local("203.0.113.50") and not is_local("8.8.8.8") and not is_local("127.0.0.1")


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("q8z3kd92mfp0xv7ls1ty") > 3.8


def test_sample_capture_end_to_end(tmp_path):
    pytest.importorskip("scapy")
    from make_sample_pcap import main as make_sample
    from netmon.capture import read_pcap

    path = tmp_path / "demo.pcap"
    make_sample(str(path))
    analyzer = Analyzer()
    read_pcap(analyzer, str(path))
    snap = analyzer.snapshot()
    found = {(a["kind"], a["source"]) for a in snap["alerts"]}
    assert found == {
        ("New device", "192.168.1.99"),
        ("Port scan", "192.168.1.99"),
        ("Risky port", "192.168.1.99"),
        ("Suspicious DNS", "192.168.1.12"),
        ("High traffic", "192.168.1.11"),
    }
    assert len(snap["devices"]) == 4  # laptop, phone, TV, intruder (the router only receives)
    assert Path(path).stat().st_size > 0
