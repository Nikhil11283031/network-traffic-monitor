"""Attack story: turning a list of alerts into "what happened, in what order".

A real attack is a chain: someone gets onto the network, looks around, breaks in, and then the victim starts
calling home or leaking data. Alerts show the steps one by one; this module joins them up:

1. Alerts are grouped by the device that did it (the actor). A MAC address (ARP spoofing) is mapped to the
   device that uses it.
2. If a device that was attacked later does something suspicious itself, the two groups are joined - that is
   the attack spreading (for example a scanned laptop that then starts beaconing).
3. Each step is placed on the attack chain (based on MITRE ATT&CK tactics): Initial access, Reconnaissance,
   Credential access, Command and control, Exfiltration / Impact.
4. A plain-language story is written, including which later stages were NOT seen - often the most useful part
   ("no sign that it got in: nothing suspicious came from the laptop afterwards").
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from .analyzer import SEVERITY_ORDER, is_local

STAGES = ["Initial access", "Reconnaissance", "Credential access", "Command and control", "Exfiltration / impact"]
STAGE_OF = {
    "New device": "Initial access",
    "Port scan": "Reconnaissance",
    "Risky port": "Credential access",
    "Brute force": "Credential access",
    "ARP spoofing": "Credential access",
    "Threat intel": "Command and control",
    "Beaconing": "Command and control",
    "Unusual TLS client": "Command and control",
    "Suspicious DNS": "Command and control",
    "Watched country": "Command and control",
    "High traffic": "Exfiltration / impact",
    "SYN flood": "Exfiltration / impact",
}
VERB = {
    "New device": "joined the network",
    "Port scan": "scanned {target} for open services",
    "Risky port": "tried a risky service on {target}",
    "Brute force": "tried to guess passwords on {target}",
    "ARP spoofing": "impersonated {target} to intercept traffic (ARP spoofing)",
    "Threat intel": "contacted {target}, a known-bad server",
    "Beaconing": "started calling home to {target} on a timer",
    "Unusual TLS client": "opened a hidden encrypted channel to {target}",
    "Suspicious DNS": "smuggled data through DNS names under {target}",
    "Watched country": "connected to {target} in a watched country",
    "High traffic": "uploaded a large amount of data",
    "SYN flood": "flooded {target} with connection attempts",
    "Anomaly (ML)": "behaved unusually (machine learning)",
    "Self-test": "self-test",
}
NEXT_STEP = {
    "Initial access": "look around the network (scanning)",
    "Reconnaissance": "break into a scanned device (password guessing, exploits)",
    "Credential access": "take control of a device - watch the targets for calling home or new programs",
    "Command and control": "steal data or spread - watch for large uploads and scans from this device",
}


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _host(value: str) -> str:
    return value.split(":")[0] if value.count(":") == 1 else value


def build(alerts: list[dict], mac_to_ip: dict | None = None) -> dict:
    """Incidents with their chain of steps, most serious first. alerts are dicts as in Analyzer.snapshot()."""
    mac_to_ip = {k.lower(): v for k, v in (mac_to_ip or {}).items()}
    alerts = [a for a in alerts if a["kind"] != "Self-test"]
    actor_of = {}
    for a in alerts:
        src = a["source"]
        actor_of[a["id"]] = mac_to_ip.get(src.lower(), src)

    groups: dict[str, list] = defaultdict(list)
    for a in alerts:
        groups[actor_of[a["id"]]].append(a)

    # Join groups when a victim of one actor later acts suspiciously itself (the attack spreading).
    parent = {actor: actor for actor in groups}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for actor, items in groups.items():
        for a in items:
            victim = _host(a["target"])
            if victim in groups and victim != actor and is_local(victim) and a["kind"] != "New device":
                first_hit = a["ts"]
                if any(b["ts"] >= first_hit and b["kind"] not in ("New device", "Anomaly (ML)")
                       for b in groups[victim]):
                    parent[find(victim)] = find(actor)

    merged: dict[str, list] = defaultdict(list)
    for actor, items in groups.items():
        merged[find(actor)].extend(items)

    incidents = []
    for root, items in merged.items():
        items.sort(key=lambda a: a["ts"])
        if all(a["kind"] == "New device" for a in items):
            continue  # a device joining on its own is not an attack story
        actors = sorted({actor_of[a["id"]] for a in items}, key=lambda h: min(b["ts"] for b in items
                                                                                if actor_of[b["id"]] == h))
        stages_seen = [s for s in STAGES if any(STAGE_OF.get(a["kind"]) == s for a in items)]
        severity = min((a["severity"] for a in items), key=lambda s: SEVERITY_ORDER.get(s, 9))
        steps = []
        for a in items:
            stage = STAGE_OF.get(a["kind"], "Unusual behaviour")
            target = _host(a["target"])
            steps.append({"ts": a["ts"], "time": _when(a["ts"]), "actor": actor_of[a["id"]], "kind": a["kind"],
                          "stage": stage, "severity": a["severity"], "target": target,
                          "text": f"{actor_of[a['id']]} " + VERB.get(a["kind"], a["kind"].lower()).format(target=target),
                          "detail": a["message"], "alert_id": a["id"],
                          "mitre": [m["id"] for m in a.get("mitre", [])]})
        incidents.append({"id": root, "title": _title(actors, stages_seen, items), "severity": severity,
                          "start": items[0]["ts"], "end": items[-1]["ts"], "actors": actors,
                          "victims": sorted({s["target"] for s in steps if is_local(s["target"])} - set(actors)),
                          "stages": stages_seen, "steps": _dedupe(steps),
                          "story": _narrative(actors, steps, stages_seen)})
    incidents.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 9), -len(i["stages"]), i["start"]))
    return {"incidents": incidents, "stages": STAGES}


def _dedupe(steps: list) -> list:
    """Repeated alerts of the same kind between the same hosts become one step with a count."""
    out, index = [], {}
    for s in steps:
        key = (s["actor"], s["kind"], s["target"])
        if key in index:
            out[index[key]]["count"] += 1
            out[index[key]]["last_time"] = s["time"]
            continue
        index[key] = len(out)
        out.append({**s, "count": 1, "last_time": s["time"]})
    return out


def _title(actors, stages, items) -> str:
    kinds = {a["kind"] for a in items}
    if len(actors) > 1:
        return f"Attack spreading from {actors[0]} to {', '.join(actors[1:])}"
    if "Initial access" in stages and len(stages) >= 2:
        return f"Intruder {actors[0]} on the network"
    if kinds & {"Threat intel", "Beaconing", "Unusual TLS client"}:
        return f"{actors[0]} may be infected"
    if kinds == {"High traffic"} or kinds <= {"High traffic", "Anomaly (ML)"}:
        return f"Large upload from {actors[0]}"
    if not is_local(actors[0]):
        return f"Attack from outside: {actors[0]}"
    return f"Suspicious activity from {actors[0]}"


def _narrative(actors, steps, stages) -> str:
    parts = []
    seen = set()
    previous = None
    for s in _dedupe(steps):
        if s["kind"] == "Anomaly (ML)" and len(steps) > 1:
            continue
        phrase = s["text"] + (f" ({s['count']} alerts, until {s['last_time']})" if s["count"] > 1 else "")
        if s["actor"] == previous:
            phrase = "it" + phrase[len(s["actor"]):]
        previous = s["actor"]
        key = (s["actor"], s["kind"])
        if key in seen:
            continue
        seen.add(key)
        parts.append(f"at {s['time']} {phrase}")
    text = "; ".join(parts)
    text = text[0].upper() + text[1:] + "." if text else ""
    if len(actors) > 1:
        text += (f" The attack appears to have spread: {', '.join(actors[1:])} was targeted first and then acted "
                 "suspiciously itself.")
    reached = stages[-1] if stages else None
    if reached in NEXT_STEP:
        text += f" Furthest stage seen: {reached}. Not seen (yet): attempts to {NEXT_STEP[reached]}."
    elif reached:
        text += f" Furthest stage seen: {reached} - the most serious stage; act now."
    if any(s["kind"] == "Anomaly (ML)" for s in steps):
        text += " Machine learning also flagged the behaviour as unusual."
    return text
