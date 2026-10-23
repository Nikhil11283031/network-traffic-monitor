"""Tests for the fast capture reader and the accuracy benchmark."""

import json
from dataclasses import astuple
from pathlib import Path

import pytest

from netmon.analyzer import Analyzer
from netmon.benchmark import Episode, cic_ids2017, from_flow_csv, load_truth, markdown, match, run, score

ROOT = Path(__file__).resolve().parent.parent
DEMO = str(ROOT / "samples" / "demo.pcap")
T0 = 1_792_000_000.0


def test_fast_reader_matches_scapy_exactly():
    pytest.importorskip("dpkt")
    from scapy.all import PcapReader

    from netmon.capture import iter_pcap_fast, to_packet_info

    slow = [p for p in (to_packet_info(x) for x in PcapReader(DEMO)) if p]
    fast = list(iter_pcap_fast(DEMO))
    assert len(fast) == len(slow) == 6264
    assert [astuple(p) for p in fast] == [astuple(p) for p in slow]


def test_cic_ids2017_schedule_in_local_time():
    eps = cic_ids2017("friday")
    scan = next(e for e in eps if e.name == "Port scan")
    # 13:55 Atlantic Daylight Time (UTC-3) on 7 July 2017 = 16:55 UTC
    assert scan.start == 1499446500.0 and "172.16.0.1" in scan.attackers and "192.168.10.50" in scan.victims
    assert scan.expected == ["Port scan"]
    assert not next(e for e in cic_ids2017("thursday") if "SQL" in e.name).in_scope
    assert cic_ids2017("monday") == []
    with pytest.raises(ValueError):
        load_truth("cicids2017-sunday")


def test_unsw_csv_groups_flows_into_episodes(tmp_path):
    rows = [  # no header, like the original UNSW-NB15_GT files: only the columns used are filled
        ["175.45.176.1", "1", "149.171.126.10", "80"] + [""] * 24 + ["1421927400", "1421927401"] + [""] * 17 + ["Reconnaissance", "1"],
        ["175.45.176.1", "1", "149.171.126.11", "80"] + [""] * 24 + ["1421927450", "1421927460"] + [""] * 17 + ["Reconnaissance", "1"],
        ["175.45.176.2", "1", "149.171.126.10", "80"] + [""] * 24 + ["1421937400", "1421937401"] + [""] * 17 + ["Exploits", "1"],
        ["59.166.0.1", "1", "149.171.126.3", "80"] + [""] * 24 + ["1421927400", "1421927401"] + [""] * 17 + ["", "0"],
    ]
    path = tmp_path / "gt.csv"
    path.write_text("\n".join(",".join(r) for r in rows))
    eps = from_flow_csv(path)
    assert [(e.name, e.in_scope) for e in eps] == [("Reconnaissance", True), ("Exploits", False)]
    assert eps[0].victims == {"149.171.126.10", "149.171.126.11"} and eps[0].end == 1421927460


def test_matching_rules():
    ep = Episode("scan", T0 + 100, T0 + 200, {"10.0.0.9"}, {"10.0.0.5"}, True, ["Port scan"])
    alert = {"id": "a", "ts": T0 + 150, "kind": "Port scan", "source": "10.0.0.9", "target": "10.0.0.5"}
    assert match(alert, ep, {})
    assert not match({**alert, "ts": T0 + 600}, ep, {})  # more than 5 minutes after the end
    assert match({**alert, "ts": T0 + 50}, ep, {})  # inside the 60 s margin before the start
    victim_only = {**alert, "source": "10.0.0.5", "target": "behaviour"}
    assert match({**victim_only, "kind": "Anomaly (ML)"}, ep, {})
    assert not match({**victim_only, "kind": "Risky port"}, ep, {})
    arp = {**alert, "kind": "ARP spoofing", "source": "DE:AD:BE:EF:00:99", "target": "10.0.0.1"}
    assert match(arp, ep, {"de:ad:be:ef:00:99": "10.0.0.9"})  # MAC addresses are mapped back to the attacker


def test_score_counts_false_alarms_and_out_of_scope():
    eps = [Episode("scan", T0, T0 + 10, {"10.0.0.9"}, {"10.0.0.5"}, True, ["Port scan"]),
           Episode("sqli", T0 + 3000, T0 + 3010, {"10.0.0.8"}, {"10.0.0.5"}, False, [])]
    alerts = [{"id": "1", "ts": T0 + 3, "kind": "Port scan", "source": "10.0.0.9", "target": "10.0.0.5", "message": "m"},
              {"id": "2", "ts": T0 + 1000, "kind": "Beaconing", "source": "10.0.0.20", "target": "1.2.3.4", "message": "fp"},
              {"id": "3", "ts": T0 + 1000, "kind": "New device", "source": "10.0.0.21", "target": "network", "message": "n"}]
    r = score(alerts, eps, capture_start=T0, capture_end=T0 + 3600)
    assert r["detected"] == 1 and r["in_scope"] == 1 and r["detection_rate"] == 1.0
    assert r["right_detector_rate"] == 1.0 and r["episodes"][0]["time_to_detect"] == 3.0
    assert r["true_positives"] == 1 and r["false_positives"] == 1 and r["precision"] == 0.5
    assert r["false_positives_per_hour"] == 1.0 and r["by_kind"]["New device"]["scored"] is False


def test_known_answer_benchmark_on_demo(tmp_path):
    pytest.importorskip("sklearn")
    from netmon.ml import AnomalyDetector
    from netmon.threatintel import ThreatIntel

    truth = load_truth(str(ROOT / "samples" / "demo-truth.json"))
    result = run(DEMO, truth, Analyzer(intel=ThreatIntel().load_dir(ROOT / "intel"), ml=AnomalyDetector()))
    assert result["detected"] == result["in_scope"] == 7
    assert result["detected_by_right_detector"] == 7
    assert result["false_positives"] == 0 and result["precision"] == 1.0
    assert result["packets"] == 6264
    text = markdown(result, "Demo")
    assert "| Attacks detected (in scope) | 7 of 7 (100.0%) |" in text
    json.dumps(result, default=str)


def test_benchmark_cli(tmp_path, capsys):
    from netmon.__main__ import main

    assert main(["benchmark", DEMO, "--truth", str(ROOT / "samples" / "demo-truth.json"), "--no-ml",
                 "--ml-learn", "40", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "demo.md").exists() and json.loads((tmp_path / "demo.json").read_text())["in_scope"] == 7


def test_truncated_capture_uses_real_packet_size(tmp_path):
    """tcpdump -s 256 saves only the start of each packet; byte counts must still use the real size."""
    from scapy.all import IP, TCP, Ether, Raw, PcapReader, wrpcap

    from netmon.capture import iter_pcap_fast, to_packet_info

    p = Ether() / IP(src="192.168.1.11", dst="203.0.113.50") / TCP(sport=5000, dport=443, flags="A") / Raw(b"u" * 1400)
    p.time = 1_792_000_000.0
    path = tmp_path / "cut.pcap"
    wrpcap(str(path), [p], snaplen=128)
    fast = list(iter_pcap_fast(str(path)))[0].length
    slow = to_packet_info(next(iter(PcapReader(str(path))))).length
    assert fast == slow == len(p) == 14 + 20 + 20 + 1400
