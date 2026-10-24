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
    assert not is_local("203.0.113.50") and not is_local("8.8.8.8")
    assert is_local("127.0.0.1")  # loopback is never a server on the internet


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
        ("ARP spoofing", "de:ad:be:ef:00:99"),
        ("Brute force", "192.168.1.99"),
        ("Beaconing", "192.168.1.12"),
        ("Unusual TLS client", "192.168.1.12"),
    }
    assert len(snap["devices"]) == 5  # router (seen through its ARP announcement), laptop, phone, TV, intruder
    assert Path(path).stat().st_size > 0



# ---------------------------------------------------------------- new detections

def test_arp_spoofing_detected_only_when_mac_changes():
    a = Analyzer()
    a.process(PacketInfo(T0, "192.168.1.1", "192.168.1.1", "ARP", 42, src_mac="aa:bb:cc:00:00:01"))
    a.process(PacketInfo(T0 + 1, "192.168.1.1", "192.168.1.10", "ARP", 42, src_mac="AA:BB:CC:00:00:01"))  # same
    assert not a.alerts
    a.process(PacketInfo(T0 + 2, "192.168.1.1", "192.168.1.10", "ARP", 42, src_mac="de:ad:be:ef:00:99"))
    alert = a.alerts[-1]
    assert alert.kind == "ARP spoofing" and alert.severity == "high" and alert.mitre[0]["id"] == "T1557.002"
    assert "aa:bb:cc:00:00:01" in alert.message


def test_brute_force_needs_many_attempts_on_a_login_port():
    a = Analyzer()
    for i in range(19):
        a.process(PacketInfo(T0 + i, "192.168.1.99", "192.168.1.10", "TCP", 60, 5000 + i, 22, "S"))
    assert not [x for x in a.alerts if x.kind == "Brute force"]
    a.process(PacketInfo(T0 + 20, "192.168.1.99", "192.168.1.10", "TCP", 60, 6000, 22, "S"))
    alert = [x for x in a.alerts if x.kind == "Brute force"][0]
    assert "20 connection attempts to SSH" in alert.message and alert.mitre[0]["id"] == "T1110"
    b = Analyzer()  # 20 attempts on a web port are not password guessing
    for i in range(25):
        b.process(PacketInfo(T0 + i, "192.168.1.99", "192.168.1.10", "TCP", 60, 5000 + i, 443, "S"))
    assert not b.alerts


def test_beaconing_needs_regular_timing():
    regular, irregular = Analyzer(), Analyzer()
    for i in range(10):
        regular.process(PacketInfo(T0 + i * 30, "192.168.1.12", "198.51.100.23", "TCP", 60, 4000 + i, 443, "S"))
    for i, t in enumerate([0, 4, 31, 33, 80, 140, 141, 200, 260, 262]):
        irregular.process(PacketInfo(T0 + t, "192.168.1.12", "198.51.100.23", "TCP", 60, 4000 + i, 443, "S"))
    assert [x.kind for x in regular.alerts] == ["Beaconing"]
    assert "every 30 seconds" in regular.alerts[0].message
    assert not irregular.alerts


def test_watched_country_alert_with_geoip():
    from netmon.geoip import GeoIP

    geo = GeoIP()
    geo.load_rows([["198.51.100.0", "198.51.100.255", "KP"], ["2001:db8::", "2001:db8::ffff", "IR"],
                   ["203.0.113.0", "203.0.113.255", "AU"], ["bad", "row", "XX"]])
    assert geo.country("198.51.100.7") == "KP" and geo.country("2001:db8::5") == "IR"
    assert geo.country("8.8.8.8") is None and geo.size == 3
    a = Analyzer(geo=geo)
    a.config.update({"watch_countries": "kp, ir"})
    a.process(PacketInfo(T0, "192.168.1.10", "203.0.113.5", "TCP", 60, 1, 443, "S"))  # AU: not watched
    a.process(PacketInfo(T0 + 1, "192.168.1.10", "198.51.100.7", "TCP", 60, 1, 443, "S"))
    a.process(PacketInfo(T0 + 2, "192.168.1.10", "198.51.100.7", "TCP", 60, 2, 443, "S"))  # once per pair
    assert [x.kind for x in a.alerts] == ["Watched country"] and "KP" in a.alerts[0].message
    countries = {t["host"]: t["country"] for t in a.snapshot()["top_talkers"]}
    assert countries["198.51.100.7"] == "KP" and countries["192.168.1.10"] is None  # local: no country


def test_config_update_validates_and_applies():
    a = Analyzer()
    result = a.update_config({"port_scan_ports": "5", "beacon_max_jitter": 2, "nonsense": 1, "heavy_bytes": -1})
    assert result["changed"] == {"port_scan_ports": 5}
    assert set(result["errors"]) == {"beacon_max_jitter", "nonsense", "heavy_bytes"}
    for i, port in enumerate(range(1, 6)):
        a.process(PacketInfo(T0 + i * 0.1, "192.168.1.99", "192.168.1.10", "TCP", 60, 61000, port, "S"))
    assert [x.kind for x in a.alerts] == ["Port scan"]


def test_acknowledge_alert():
    a = Analyzer()
    a.process(PacketInfo(T0, "192.168.1.99", "192.168.1.1", "TCP", 60, 1, 23, "S"))
    alert_id = a.alerts[0].id
    assert a.acknowledge(alert_id, "checked - my own test").acked
    assert a.snapshot()["alerts"][0]["ack_note"] == "checked - my own test"
    assert a.acknowledge("missing") is None


def test_dns_replies_from_the_router_are_not_a_port_scan():
    """Found in a live test: the router answers DNS lookups to many random ports on the laptop."""
    from netmon.analyzer import Analyzer, PacketInfo

    a = Analyzer()
    for i in range(60):  # 60 DNS replies to 60 different client ports in 6 seconds
        a.process(PacketInfo(1_792_000_000 + i * 0.1, "192.168.1.1", "192.168.1.103", "DNS", 120, 53, 50000 + i * 7))
        a.process(PacketInfo(1_792_000_000 + i * 0.1, "142.250.66.78", "192.168.1.103", "UDP", 1200, 443, 60000 + i))
    assert not [x for x in a.alerts if x.kind == "Port scan"]
    for i, port in enumerate(range(1, 40)):  # a real UDP scan from a random source port is still caught
        a.process(PacketInfo(1_792_000_010 + i * 0.05, "192.168.1.66", "192.168.1.103", "UDP", 60, 41000, port))
    assert [x.source for x in a.alerts if x.kind == "Port scan"] == ["192.168.1.66"]


def test_free_port_skips_a_busy_port():
    import socket

    from netmon.__main__ import free_port

    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    port = busy.getsockname()[1]
    try:
        assert free_port("127.0.0.1", port) == port + 1 or free_port("127.0.0.1", port) > port
    finally:
        busy.close()


def test_downloads_and_multicast_are_not_alarms():
    """Found in a live test: a video download looked like 'High traffic' and mDNS looked like beaconing."""
    from netmon.analyzer import Analyzer, PacketInfo, is_local

    assert is_local("224.0.0.251") and is_local("255.255.255.255") and is_local("ff02::fb") and is_local("169.254.1.2")
    assert not is_local("223.255.0.1") and not is_local("240.0.0.1") and not is_local("8.8.8.8")
    a = Analyzer()
    for i in range(6000):  # 9 MB downloaded from a video server in 6 seconds
        a.process(PacketInfo(1_792_000_000 + i * 0.001, "116.255.21.202", "192.168.1.103", "TCP", 1500, 443, 50000, "A"))
    for i in range(14):  # the Mac announcing itself on mDNS every 20 seconds
        a.process(PacketInfo(1_792_000_000 + i * 20, "192.168.1.103", "224.0.0.251", "UDP", 200, 51000 + i, 5353))
    assert not [x.kind for x in a.alerts]
    device = a.privacy.report()["devices"][0]
    assert device["sent"] == 0  # the mDNS packets to 224.0.0.251 are not counted as data sent to the internet
    assert [p["received"] for p in device["parties"]] == [9_000_000]  # only the download


def test_ipv6_addresses_are_shown_under_their_device():
    from netmon.analyzer import Analyzer, PacketInfo

    a = Analyzer()
    a.process(PacketInfo(1_792_000_000, "192.168.1.103", "142.250.66.78", "TCP", 60, 1, 443, "S", src_mac="aa:bb:cc:dd:ee:01"))
    a.process(PacketInfo(1_792_000_001, "fe80::1c2:3ff:fe04:5", "ff02::fb", "UDP", 60, 5353, 5353, src_mac="AA:BB:CC:DD:EE:01"))
    a.process(PacketInfo(1_792_000_002, "fe80::99", "ff02::fb", "UDP", 60, 5353, 5353, src_mac="aa:bb:cc:dd:ee:99"))
    devices = {d["ip"]: d for d in a.snapshot()["devices"]}
    assert devices["192.168.1.103"]["also"] == ["fe80::1c2:3ff:fe04:5"]
    assert set(devices) == {"192.168.1.103", "fe80::99"}  # an IPv6-only device stays on its own


def test_second_copy_is_detected(monkeypatch):
    import netmon.__main__ as cli

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"status": {"source": "live: en0"}}'

    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout: Resp())
    assert cli.running_monitor(5050) == "port 5050, watching live: en0"
