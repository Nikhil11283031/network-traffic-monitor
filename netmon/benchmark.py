"""Accuracy benchmark: run the monitor over a labelled capture and score every alert against the known attacks.

Ground truth ("answer key") is a list of attack episodes: a name, a time window, the attacking addresses and the
victim addresses. It can come from:
  - a built-in preset for each day of CIC-IDS2017 (official schedule from the Canadian Institute for Cybersecurity),
  - the UNSW-NB15 ground-truth CSV (srcip, dstip, stime, ltime, attack_cat),
  - a simple JSON file: {"episodes": [{"name", "start", "end", "attackers": [...], "victims": [...]}]}
    with start/end as epoch seconds or ISO 8601 times.

Scoring rules (kept simple and stated in the report so the numbers can be checked):
  - An alert "matches" an episode if it falls inside the episode's window (from 60 s before the start to 5 minutes
    after the end) and involves one of the episode's attackers. Alerts that only name a victim count when they
    describe the victim's own behaviour (ML anomaly, high traffic, flood).
  - An episode is detected if at least one alert matches it. Time to detect = first matching alert - start.
  - An alert that matches no episode is a false positive. Low-severity "new device" alerts are reported but not
    counted in precision, because a network full of new devices is normal at the start of any capture.
  - Each episode is marked in scope or out of scope: attacks that need packet contents (SQL injection, XSS,
    Heartbleed, exploits) cannot be seen by a monitor that only looks at who talks to whom, so they are reported
    separately instead of being silently counted as misses.
"""

from __future__ import annotations

import csv
import json
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

PRE_WINDOW, POST_WINDOW = 60, 300
VICTIM_SIDE_KINDS = {"Anomaly (ML)", "High traffic", "SYN flood"}
NOT_SCORED = {"New device"}


@dataclass
class Episode:
    name: str
    start: float
    end: float
    attackers: set = field(default_factory=set)
    victims: set = field(default_factory=set)
    in_scope: bool = True
    expected: list = field(default_factory=list)  # alert types designed to catch it


# ------------------------------------------------------------------------------------------------ ground truth

# CIC-IDS2017 attack schedule, from https://www.unb.ca/cic/datasets/ids-2017.html. Times are local (Atlantic
# Daylight Time, UTC-3). Inside the captures, traffic from the external attacker passes the lab firewall, so it
# appears as 172.16.0.1; both addresses are listed. Victims are listed with internal and public addresses.
_CIC_ATTACKER = ["205.174.165.73", "172.16.0.1"]
_WEB = ["192.168.10.50", "205.174.165.68"]
CIC_IDS2017 = {
    "monday": ("2017-07-03", []),  # benign traffic only: every alert is a false alarm
    "tuesday": ("2017-07-04", [
        ("FTP-Patator (FTP password guessing)", "09:20", "10:20", _CIC_ATTACKER, _WEB, True, ["Brute force", "Risky port"]),
        ("SSH-Patator (SSH password guessing)", "14:00", "15:00", _CIC_ATTACKER, _WEB, True, ["Brute force"]),
    ]),
    "wednesday": ("2017-07-05", [
        ("DoS slowloris", "09:47", "10:10", _CIC_ATTACKER, _WEB, True, ["SYN flood", "Anomaly (ML)"]),
        ("DoS Slowhttptest", "10:14", "10:35", _CIC_ATTACKER, _WEB, True, ["SYN flood", "Anomaly (ML)"]),
        ("DoS Hulk", "10:43", "11:00", _CIC_ATTACKER, _WEB, True, ["SYN flood", "Anomaly (ML)"]),
        ("DoS GoldenEye", "11:10", "11:23", _CIC_ATTACKER, _WEB, True, ["SYN flood", "Anomaly (ML)"]),
        ("Heartbleed", "15:12", "15:32", _CIC_ATTACKER + ["172.16.0.11"], ["192.168.10.51", "205.174.165.66"],
         False, []),
    ]),
    "thursday": ("2017-07-06", [
        ("Web attack: brute force", "09:20", "10:00", _CIC_ATTACKER, _WEB, False, []),
        ("Web attack: XSS", "10:15", "10:35", _CIC_ATTACKER, _WEB, False, []),
        ("Web attack: SQL injection", "10:40", "10:42", _CIC_ATTACKER, _WEB, False, []),
        ("Infiltration: Metasploit (Windows Vista)", "14:19", "14:35", _CIC_ATTACKER, ["192.168.10.8"], False, []),
        ("Infiltration: Cool disk (Mac)", "14:53", "15:00", _CIC_ATTACKER, ["192.168.10.25"], False, []),
        ("Infiltration: internal port scan from the infected PC", "15:04", "15:45", ["192.168.10.8"],
         [], True, ["Port scan", "Anomaly (ML)"]),
    ]),
    "friday": ("2017-07-07", [
        ("Botnet ARES", "10:02", "11:02", _CIC_ATTACKER,
         ["192.168.10.15", "192.168.10.9", "192.168.10.14", "192.168.10.5", "192.168.10.8"], True,
         ["Beaconing", "Anomaly (ML)", "Threat intel"]),
        ("Port scan", "13:55", "15:29", _CIC_ATTACKER, _WEB, True, ["Port scan"]),
        ("DDoS LOIT", "15:56", "16:16", ["205.174.165.69", "205.174.165.70", "205.174.165.71"] + _CIC_ATTACKER,
         _WEB, True, ["SYN flood", "High traffic", "Anomaly (ML)"]),
    ]),
}
CIC_UTC_OFFSET = -3


def cic_ids2017(day: str, utc_offset: float = CIC_UTC_OFFSET) -> list[Episode]:
    date, rows = CIC_IDS2017[day.lower()]
    tz = timezone(timedelta(hours=utc_offset))

    def epoch(hm):
        return datetime.fromisoformat(f"{date}T{hm}:00").replace(tzinfo=tz).timestamp()

    return [Episode(name, epoch(a), epoch(b), set(att), set(vic), scope, list(exp))
            for name, a, b, att, vic, scope, exp in rows]


def _time(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def from_json(path: str | Path) -> list[Episode]:
    data = json.loads(Path(path).read_text())
    return [Episode(e["name"], _time(e["start"]), _time(e["end"]), set(e.get("attackers", [])),
                    set(e.get("victims", [])), e.get("in_scope", True), e.get("expected", []))
            for e in data["episodes"]]


UNSW_COLUMNS = ["srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
                "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb",
                "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt",
                "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
                "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
                "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label"]
UNSW_IN_SCOPE = {"reconnaissance": ["Port scan"], "dos": ["SYN flood", "Anomaly (ML)"],
                 "fuzzers": ["Anomaly (ML)", "Port scan"], "worms": ["Port scan", "Anomaly (ML)"],
                 "generic": ["Anomaly (ML)"], "backdoor": ["Risky port", "Beaconing"],
                 "backdoors": ["Risky port", "Beaconing"]}


def from_flow_csv(path: str | Path, gap: float = 300) -> list[Episode]:
    """Episodes from a labelled flow file (UNSW-NB15 format, with or without a header row): attack flows of the
    same category are joined into one episode until there is a gap of more than `gap` seconds."""
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        first = next(reader, None)
        if first is None:
            return []
        header = [h.strip().lower() for h in first]
        if "srcip" in header:
            cols = header
        else:
            cols = [c.lower() for c in UNSW_COLUMNS]
            rows.append(first)
        idx = {name: cols.index(name) for name in ("srcip", "dstip", "stime", "ltime", "attack_cat")}
        rows.extend(reader)
    flows = defaultdict(list)
    for r in rows:
        try:
            cat = r[idx["attack_cat"]].strip()
            if not cat or cat.lower() in ("normal", "benign", "-"):
                continue
            flows[cat].append((float(r[idx["stime"]]), float(r[idx["ltime"]]), r[idx["srcip"]].strip(),
                               r[idx["dstip"]].strip()))
        except (IndexError, ValueError):
            continue
    episodes = []
    for cat, items in flows.items():
        items.sort()
        current = None
        for start, end, src, dst in items:
            if current is None or start - current.end > gap:
                scope = UNSW_IN_SCOPE.get(cat.lower())
                current = Episode(cat, start, end, set(), set(), scope is not None, scope or [])
                episodes.append(current)
            current.end = max(current.end, end)
            current.attackers.add(src)
            current.victims.add(dst)
    return sorted(episodes, key=lambda e: e.start)


def load_truth(spec: str, utc_offset: float | None = None) -> list[Episode]:
    """spec: 'cicids2017-<day>', a .json file or a labelled flow .csv."""
    if spec.lower().startswith("cicids2017-"):
        day = spec.split("-", 1)[1]
        if day not in CIC_IDS2017:
            raise ValueError(f"Unknown CIC-IDS2017 day '{day}'. Use one of: {', '.join(CIC_IDS2017)}")
        return cic_ids2017(day, CIC_UTC_OFFSET if utc_offset is None else utc_offset)
    if spec.lower().endswith(".json"):
        return from_json(spec)
    return from_flow_csv(spec)


# ------------------------------------------------------------------------------------------------ scoring

def _alert_hosts(alert: dict, mac_to_ip: dict) -> set:
    hosts = {mac_to_ip.get(alert["source"].lower(), alert["source"])}
    target = str(alert["target"]).rsplit(":", 1)[0] if str(alert["target"]).count(":") == 1 else str(alert["target"])
    hosts.add(target)
    return hosts


def match(alert: dict, episode: Episode, mac_to_ip: dict) -> bool:
    if not (episode.start - PRE_WINDOW <= alert["ts"] <= episode.end + POST_WINDOW):
        return False
    hosts = _alert_hosts(alert, mac_to_ip)
    if hosts & episode.attackers:
        return True
    return alert["kind"] in VICTIM_SIDE_KINDS and bool(hosts & episode.victims)


def score(alerts: list[dict], episodes: list[Episode], mac_to_ip: dict | None = None,
          capture_start: float | None = None, capture_end: float | None = None) -> dict:
    mac_to_ip = {k.lower(): v for k, v in (mac_to_ip or {}).items()}
    in_capture = [e for e in episodes if capture_start is None or (e.end >= capture_start and e.start <= capture_end)]
    per_episode = []
    matched_alerts = set()
    for ep in in_capture:
        hits = [a for a in alerts if match(a, ep, mac_to_ip)]
        matched_alerts.update(a["id"] for a in hits)
        right = [a for a in hits if a["kind"] in ep.expected]
        first = min((a["ts"] for a in (right or hits)), default=None)
        per_episode.append({
            "name": ep.name, "in_scope": ep.in_scope, "expected": ep.expected,
            "start": ep.start, "end": ep.end, "detected": bool(hits),
            "time_to_detect": None if first is None else round(max(0.0, first - ep.start), 1),
            "alert_kinds": dict(Counter(a["kind"] for a in hits)),
            "detected_by_expected": bool(right),
        })
    scored = [a for a in alerts if a["kind"] not in NOT_SCORED]
    tp = [a for a in scored if a["id"] in matched_alerts]
    fp = [a for a in scored if a["id"] not in matched_alerts]
    hours = max((capture_end - capture_start) / 3600, 1e-9) if capture_start is not None else None
    by_kind = {}
    for kind in sorted({a["kind"] for a in alerts}):
        k_all = [a for a in alerts if a["kind"] == kind]
        k_tp = sum(1 for a in k_all if a["id"] in matched_alerts)
        by_kind[kind] = {"alerts": len(k_all), "true": k_tp, "false": len(k_all) - k_tp,
                         "precision": round(k_tp / len(k_all), 3) if k_all else None,
                         "scored": kind not in NOT_SCORED}
    scope = [e for e in per_episode if e["in_scope"]]
    detected = [e for e in scope if e["detected"]]
    right = [e for e in scope if e["detected_by_expected"]]
    ttd = [e["time_to_detect"] for e in detected if e["time_to_detect"] is not None]
    return {
        "episodes_total": len(per_episode),
        "in_scope": len(scope),
        "detected": len(detected),
        "detection_rate": round(len(detected) / len(scope), 3) if scope else None,
        "detected_by_right_detector": len(right),
        "right_detector_rate": round(len(right) / len(scope), 3) if scope else None,
        "out_of_scope_detected": sum(1 for e in per_episode if not e["in_scope"] and e["detected"]),
        "median_time_to_detect": sorted(ttd)[len(ttd) // 2] if ttd else None,
        "alerts_scored": len(scored),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "precision": round(len(tp) / len(scored), 3) if scored else None,
        "false_positives_per_hour": round(len(fp) / hours, 2) if hours else None,
        "episodes_outside_capture": len(episodes) - len(in_capture),
        "episodes": per_episode,
        "by_kind": by_kind,
        "false_positive_examples": [{"kind": a["kind"], "message": a["message"]} for a in fp[:15]],
    }


# ------------------------------------------------------------------------------------------------ running

def run(capture: str, truth: list[Episode], analyzer, progress=None) -> dict:
    """Analyse the whole capture with the given analyser, then score it."""
    from .capture import read_pcap

    alerts: list[dict] = []
    analyzer.listeners.append(lambda alert: alerts.append(asdict(alert)))
    analyzer.config.max_alerts = 10_000_000  # keep everything for scoring
    from collections import deque

    analyzer.alerts = deque(analyzer.alerts, maxlen=None)
    started = time.time()
    read_pcap(analyzer, capture, progress=progress)
    seconds = time.time() - started
    result = score(alerts, truth, mac_to_ip={mac: ip for ip, mac in analyzer.ip_mac.items()},
                   capture_start=analyzer.first_ts, capture_end=analyzer.last_ts)
    result.update({
        "capture": Path(capture).name, "packets": analyzer.packets, "bytes": analyzer.bytes,
        "capture_seconds": round((analyzer.last_ts or 0) - (analyzer.first_ts or 0), 1),
        "processing_seconds": round(seconds, 1),
        "packets_per_second": round(analyzer.packets / seconds) if seconds else None,
        "rules": {"window_before_s": PRE_WINDOW, "window_after_s": POST_WINDOW,
                  "victim_side_kinds": sorted(VICTIM_SIDE_KINDS), "not_scored": sorted(NOT_SCORED)},
    })
    return result


def _pct(x):
    return "-" if x is None else f"{x * 100:.1f}%"


def markdown(result: dict, title: str = "Benchmark") -> str:
    when = lambda ts: datetime.fromtimestamp(ts, timezone.utc).strftime("%d %b %H:%M:%S UTC")  # noqa: E731
    lines = [f"# {title}", "",
             f"Capture `{result['capture']}`: {result['packets']:,} packets, "
             f"{result['capture_seconds'] / 3600:.2f} hours of traffic, analysed in {result['processing_seconds']:.0f} s "
             f"({result['packets_per_second'] or 0:,} packets/s).", "",
             "| Measure | Result |", "| --- | --- |",
             f"| Attacks detected (in scope) | {result['detected']} of {result['in_scope']} "
             f"({_pct(result['detection_rate'])}) |",
             f"| Caught by the detector built for that attack | {result['detected_by_right_detector']} of "
             f"{result['in_scope']} ({_pct(result['right_detector_rate'])}) |",
             f"| Median time to detect | {'-' if result['median_time_to_detect'] is None else str(result['median_time_to_detect']) + ' s'} |",
             f"| Alert precision | {_pct(result['precision'])} ({result['true_positives']} true, "
             f"{result['false_positives']} false) |",
             f"| False alarms per hour | {result['false_positives_per_hour']} |",
             f"| Out-of-scope attacks noticed anyway | {result['out_of_scope_detected']} |", "",
             "## Attacks", "", "| Attack | Window | In scope | Detected | Right detector | Time to detect | Alerts |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for e in result["episodes"]:
        kinds = ", ".join(f"{k} x{n}" for k, n in sorted(e["alert_kinds"].items())) or "-"
        lines.append(f"| {e['name']} | {when(e['start'])}-{when(e['end'])} | {'yes' if e['in_scope'] else 'no'} | "
                     f"{'yes' if e['detected'] else '**no**'} | "
                     f"{'yes' if e['detected_by_expected'] else ('no' if e['in_scope'] else '-')} | "
                     f"{'-' if e['time_to_detect'] is None else str(e['time_to_detect']) + ' s'} | {kinds} |")
    lines += ["", "## Detectors", "", "| Alert type | Alerts | Matched an attack | False | Precision |",
              "| --- | --- | --- | --- | --- |"]
    for kind, k in result["by_kind"].items():
        lines.append(f"| {kind}{'' if k['scored'] else ' (not scored)'} | {k['alerts']} | {k['true']} | "
                     f"{k['false']} | {_pct(k['precision'])} |")
    if result["false_positive_examples"]:
        lines += ["", "## Examples of false alarms", ""] + [f"- {x['kind']}: {x['message']}"
                                                            for x in result["false_positive_examples"]]
    lines += ["", "## Scoring rules", "",
              f"An alert matches an attack if it is raised between {PRE_WINDOW} s before the attack starts and "
              f"{POST_WINDOW} s after it ends, and involves an attacking address (or, for "
              f"{', '.join(sorted(VICTIM_SIDE_KINDS))}, a victim address). An attack is detected if any alert "
              "matches it. 'Right detector' means one of those alerts came from the detector designed for that kind "
              "of attack; time to detect is measured from that alert, and 0 s means it fired within the "
              f"{PRE_WINDOW} s margin before the listed start (schedules are often given only to the minute). "
              "Alerts that match no attack are false alarms; new-device alerts are not scored. Attacks that can only "
              "be seen in packet contents are marked out of scope."]
    if result["episodes_outside_capture"]:
        lines += ["", f"{result['episodes_outside_capture']} attack(s) in the answer key fall outside this capture's "
                      "time range and were left out. If that is unexpected, check the --utc-offset."]
    return "\n".join(lines) + "\n"
