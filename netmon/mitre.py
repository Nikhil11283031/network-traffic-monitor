"""MITRE ATT&CK mapping.

MITRE ATT&CK (https://attack.mitre.org) is the industry's shared catalogue of attacker behaviour. Tagging each
alert with its technique lets a security team look up how the attack works, what usually comes next and how to
defend against it, and lets the alerts be compared with other tools that use the same IDs.

The mapping is a best match for what the monitor can see from traffic; it is not proof that the technique was
used.
"""

from __future__ import annotations

TECHNIQUES = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1498.001": ("Network Denial of Service: Direct Network Flood", "Impact"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.005": ("Remote Services: VNC", "Lateral Movement"),
    "T1071.002": ("Application Layer Protocol: File Transfer Protocols", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1568.002": ("Dynamic Resolution: Domain Generation Algorithms", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1200": ("Hardware Additions", "Initial Access"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
}

# Risky ports -> the technique that service is usually abused for.
PORT_TECHNIQUES = {
    21: ["T1071.002"],
    23: ["T1021"],
    445: ["T1021.002"],
    1433: ["T1190"],
    3389: ["T1021.001"],
    4444: ["T1571"],
    5900: ["T1021.005"],
    6667: ["T1071", "T1571"],
}

KIND_TECHNIQUES = {
    "Port scan": ["T1046"],
    "SYN flood": ["T1498.001"],
    "High traffic": ["T1048", "T1041"],
    "Suspicious DNS": ["T1071.004", "T1568.002"],
    "New device": ["T1200"],
    "Threat intel": ["T1071"],
    "Anomaly (ML)": [],  # an anomaly is "something unusual", not a specific technique
}


def technique(tid: str) -> dict:
    name, tactic = TECHNIQUES[tid]
    url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
    return {"id": tid, "name": name, "tactic": tactic, "url": url}


def techniques_for(kind: str, port: int | None = None) -> list[dict]:
    ids = PORT_TECHNIQUES.get(port, []) if kind == "Risky port" else KIND_TECHNIQUES.get(kind, [])
    return [technique(t) for t in ids]
