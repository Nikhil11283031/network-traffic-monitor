"""Responder: turns alerts into concrete defensive actions, for a person to approve.

For each incident it proposes one action - block an outside server, isolate a device on your network, close a
risky port or block a domain - with the exact firewall rule for macOS (pf), Linux (iptables), Windows
(PowerShell) and plain router instructions.

Safety: the responder NEVER changes anything by itself. Approving an action only adds it to a reviewed rules
file you can download and apply yourself. Automatic blocking is dangerous: an attacker can trigger alerts that
make a tool block your own router, and a false positive can cut off a family member's laptop.
"""

from __future__ import annotations

import hashlib
import ipaddress
import threading
import time

from .analyzer import is_local

PLATFORMS = {"pf": "macOS (pf)", "iptables": "Linux (iptables)", "powershell": "Windows (PowerShell)",
             "router": "Router / manual"}


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _block_remote(ip: str) -> dict:
    return {
        "pf": f"block drop out quick to {ip}\nblock drop in quick from {ip}",
        "iptables": f"iptables -A OUTPUT -d {ip} -j DROP\niptables -A INPUT -s {ip} -j DROP",
        "powershell": (f'New-NetFirewallRule -DisplayName "netmon block {ip} out" -Direction Outbound '
                       f"-RemoteAddress {ip} -Action Block\n"
                       f'New-NetFirewallRule -DisplayName "netmon block {ip} in" -Direction Inbound '
                       f"-RemoteAddress {ip} -Action Block"),
        "router": f"In your router's firewall or parental-control settings, block all traffic to and from {ip}.",
    }


def _isolate_local(ip: str, mac: str | None) -> dict:
    return {
        "pf": f"block drop quick from {ip} to any\nblock drop quick from any to {ip}",
        "iptables": f"iptables -A INPUT -s {ip} -j DROP\niptables -A FORWARD -s {ip} -j DROP",
        "powershell": (f'New-NetFirewallRule -DisplayName "netmon isolate {ip}" -Direction Inbound '
                       f"-RemoteAddress {ip} -Action Block"),
        "router": (f"In your router's device list, block or pause the device {ip}"
                   + (f" (MAC {mac})" if mac else "") + ", then change the Wi-Fi password."),
    }


def _close_port(ip: str, port: int) -> dict:
    return {
        "pf": f"block drop in quick proto tcp to {ip} port {port}",
        "iptables": f"iptables -A INPUT -p tcp --dport {port} -j DROP",
        "powershell": (f'New-NetFirewallRule -DisplayName "netmon close port {port}" -Direction Inbound '
                       f"-Protocol TCP -LocalPort {port} -Action Block"),
        "router": (f"On {ip}, turn off the service on port {port} if it is not needed. On the router, make sure "
                   f"port {port} is not forwarded from the internet."),
    }


def _block_domain(domain: str) -> dict:
    return {
        "pf": f"# pf works on IP addresses. Block the name instead with your hosts file:\n"
              f"echo '0.0.0.0 {domain}' | sudo tee -a /etc/hosts",
        "iptables": f"echo '0.0.0.0 {domain}' | sudo tee -a /etc/hosts",
        "powershell": (f"Add-Content -Path $env:windir\\System32\\drivers\\etc\\hosts "
                       f"-Value '0.0.0.0 {domain}'"),
        "router": f"Add {domain} to your router's (or Pi-hole's) DNS block list.",
    }


class Responder:
    def __init__(self):
        self.decisions: dict[str, dict] = {}  # action id -> {"status": approved/dismissed, "at": ts}
        self.lock = threading.Lock()

    @staticmethod
    def _id(kind: str, target: str) -> str:
        return hashlib.sha1(f"{kind}|{target}".encode()).hexdigest()[:10]

    def propose(self, analyzer) -> list[dict]:
        snap = analyzer.snapshot()
        mac_of = {d["ip"]: d.get("mac") for d in snap["devices"]}
        ip_of_mac = {mac.lower(): ip for ip, mac in analyzer.ip_mac.items()} if hasattr(analyzer, "ip_mac") else {}
        actions: dict[str, dict] = {}

        def add(kind, target, title, reason, commands, severity, alert):
            action_id = self._id(kind, target)
            if action_id in actions:
                actions[action_id]["alerts"].append(alert["id"])
                return
            decision = self.decisions.get(action_id, {})
            actions[action_id] = {"id": action_id, "kind": kind, "target": target, "title": title,
                                  "reason": reason, "severity": severity, "commands": commands,
                                  "alerts": [alert["id"]], "status": decision.get("status", "proposed")}

        for a in sorted(snap["alerts"], key=lambda x: x["ts"]):
            kind, src, tgt = a["kind"], a["source"], a["target"]
            if kind in ("Threat intel", "High traffic", "Watched country", "Beaconing"):
                remote = tgt if _valid_ip(tgt) else None
                if kind == "High traffic":  # target is "any"; the destination is in the message
                    remote = next((w.strip("().,") for w in a["message"].split() if _valid_ip(w.strip("().,"))
                                   and not is_local(w.strip("().,"))), None)
                if remote and not is_local(remote):
                    add("block-remote", remote, f"Block outside server {remote}",
                        f"{kind}: {a['message']}", _block_remote(remote), a["severity"], a)
                elif kind == "Threat intel" and not _valid_ip(tgt):
                    add("block-domain", tgt, f"Block domain {tgt}", f"{kind}: {a['message']}",
                        _block_domain(tgt), a["severity"], a)
            elif kind in ("Port scan", "Brute force", "SYN flood", "ARP spoofing"):
                attacker = src
                if kind == "ARP spoofing":  # the source is a MAC; the attacker's own IP is the one seen with it
                    attacker = ip_of_mac.get(src.lower()) or next(
                        (ip for ip, mac in mac_of.items() if (mac or "").lower() == src.lower()), None)
                if attacker and _valid_ip(attacker):
                    title = (f"Isolate device {attacker}" if is_local(attacker) else f"Block attacker {attacker}")
                    commands = (_isolate_local(attacker, mac_of.get(attacker)) if is_local(attacker)
                                else _block_remote(attacker))
                    add("isolate" if is_local(attacker) else "block-remote", attacker, title,
                        f"{kind}: {a['message']}", commands, a["severity"], a)
            elif kind == "Risky port":
                host, _, port = tgt.rpartition(":")
                if port.isdigit() and _valid_ip(host):
                    add("close-port", f"{host}:{port}", f"Close port {port} on {host}",
                        f"{kind}: {a['message']}", _close_port(host, int(port)), a["severity"], a)
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(actions.values(), key=lambda x: (x["status"] == "dismissed", order.get(x["severity"], 9)))

    def decide(self, action_id: str, status: str) -> bool:
        if status not in ("approved", "dismissed", "proposed"):
            return False
        with self.lock:
            if status == "proposed":
                self.decisions.pop(action_id, None)
            else:
                self.decisions[action_id] = {"status": status, "at": time.time()}
        return True

    def script(self, analyzer, platform: str) -> str:
        """The approved actions as one file to review and apply by hand."""
        if platform not in PLATFORMS:
            raise ValueError(f"unknown platform {platform}")
        approved = [a for a in self.propose(analyzer) if a["status"] == "approved"]
        comment = "#" if platform != "router" else "-"
        lines = [f"{comment} Firewall rules approved in the network monitor - {PLATFORMS[platform]}",
                 f"{comment} Generated {time.strftime('%Y-%m-%d %H:%M')}. REVIEW EVERY LINE BEFORE APPLYING.", ""]
        if platform == "pf":
            lines += ["# Save as /etc/pf.anchors/netmon, then: sudo pfctl -a netmon -f /etc/pf.anchors/netmon", ""]
        if not approved:
            lines.append(f"{comment} No actions approved yet.")
        for a in approved:
            lines += [f"{comment} {a['title']} - {a['reason'][:150]}", a["commands"][platform], ""]
        return "\n".join(lines) + "\n"
