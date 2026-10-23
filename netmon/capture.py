"""Turning packets into PacketInfo records, from a live network interface or a saved .pcap file."""

from __future__ import annotations

import time

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, IPv6, PcapReader, sniff

from .analyzer import Analyzer, PacketInfo


def to_packet_info(pkt) -> PacketInfo | None:
    """Pull out the fields the analyser needs. Returns None for packets it cannot use."""
    ts = float(pkt.time)
    length = len(pkt)
    mac = pkt[Ether].src if Ether in pkt else None

    if ARP in pkt:
        # The MAC inside the ARP message is the one the sender claims for its IP address.
        return PacketInfo(ts, pkt[ARP].psrc, pkt[ARP].pdst, "ARP", length, src_mac=pkt[ARP].hwsrc or mac)

    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return None

    if TCP in pkt:
        return PacketInfo(ts, src, dst, "TCP", length, pkt[TCP].sport, pkt[TCP].dport,
                          flags=str(pkt[TCP].flags), src_mac=mac)
    if UDP in pkt:
        query = None
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            query = pkt[DNSQR].qname.decode(errors="replace")
        proto = "DNS" if (pkt[UDP].dport == 53 or pkt[UDP].sport == 53) else "UDP"
        return PacketInfo(ts, src, dst, proto, length, pkt[UDP].sport, pkt[UDP].dport,
                          dns_query=query, src_mac=mac)
    if ICMP in pkt:
        return PacketInfo(ts, src, dst, "ICMP", length, src_mac=mac)
    return PacketInfo(ts, src, dst, "OTHER", length, src_mac=mac)


def _handle(analyzer: Analyzer, pkt, on_alert):
    info = to_packet_info(pkt)
    if info is None:
        return
    for alert in analyzer.process(info):
        if on_alert:
            on_alert(alert)


def live_capture(analyzer: Analyzer, iface: str | None = None, bpf: str | None = None, on_alert=None,
                 stop_event=None):
    """Watch a network interface. Needs administrator rights (sudo on macOS and Linux)."""
    sniff(iface=iface, filter=bpf, store=False, prn=lambda pkt: _handle(analyzer, pkt, on_alert),
          stop_filter=(lambda _pkt: stop_event.is_set()) if stop_event else None)


def read_pcap(analyzer: Analyzer, path: str, speed: float = 0, on_alert=None):
    """Analyse a saved capture. With speed > 0 it is replayed in (sped-up) real time so the dashboard
    animates, e.g. speed=5 plays it five times faster than it was recorded."""
    previous = None
    with PcapReader(path) as reader:
        for pkt in reader:
            if speed > 0:
                now = float(pkt.time)
                if previous is not None and now > previous:
                    time.sleep(min((now - previous) / speed, 2.0))
                previous = now
            _handle(analyzer, pkt, on_alert)
    for alert in analyzer.finish():
        if on_alert:
            on_alert(alert)
