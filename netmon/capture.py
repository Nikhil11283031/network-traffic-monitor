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
        length = max(length, len(pkt) - len(pkt[IP]) + (pkt[IP].len or 0))  # real size if the capture was cut short
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        length = max(length, len(pkt) - len(pkt[IPv6]) + 40 + (pkt[IPv6].plen or 0))
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


# ---------------------------------------------------------------------------------------------- fast reader

_TCP_LETTERS = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U"), (0x40, "E"),
                (0x80, "C")]


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _dpkt_info(ts: float, buf: bytes, linktype: int):
    """The same PacketInfo as to_packet_info(), parsed with dpkt - about 10 times faster than scapy."""
    import socket

    import dpkt

    length, mac = len(buf), None
    l2 = {1: 14, 113: 16, 0: 4, 108: 4}.get(linktype, 0)  # link-layer header size
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            mac, l3 = _mac(eth.src), eth.data
        elif linktype == 113:  # Linux "cooked" capture
            l3 = dpkt.sll.SLL(buf).data
        elif linktype in (0, 108):  # BSD loopback (lo0 on macOS)
            l3 = dpkt.loopback.Loopback(buf).data
        elif linktype in (12, 14, 101, 228, 229):  # raw IP
            l3 = dpkt.ip.IP(buf) if buf[:1] and buf[0] >> 4 == 4 else dpkt.ip6.IP6(buf)
        else:
            return None
    except (dpkt.UnpackError, IndexError, ValueError):
        return None

    if isinstance(l3, dpkt.arp.ARP):
        try:
            return PacketInfo(ts, socket.inet_ntoa(l3.spa), socket.inet_ntoa(l3.tpa), "ARP", length,
                              src_mac=_mac(l3.sha) or mac)
        except OSError:
            return None
    if isinstance(l3, dpkt.ip.IP):
        src, dst = socket.inet_ntop(socket.AF_INET, l3.src), socket.inet_ntop(socket.AF_INET, l3.dst)
        wire = l3.len
    elif isinstance(l3, dpkt.ip6.IP6):
        src, dst = socket.inet_ntop(socket.AF_INET6, l3.src), socket.inet_ntop(socket.AF_INET6, l3.dst)
        wire = 40 + l3.plen
    else:
        return None
    # Captures are often saved with only the first bytes of each packet (tcpdump -s); the IP header still holds
    # the real size, so use that for byte counts.
    length = max(length, l2 + wire)
    l4 = l3.data
    if isinstance(l4, dpkt.tcp.TCP):
        flags = "".join(letter for bit, letter in _TCP_LETTERS if l4.flags & bit)
        return PacketInfo(ts, src, dst, "TCP", length, l4.sport, l4.dport, flags=flags, src_mac=mac)
    if isinstance(l4, dpkt.udp.UDP):
        query = None
        is_dns = l4.dport == 53 or l4.sport == 53
        if is_dns and l4.dport == 53:
            try:
                dns = dpkt.dns.DNS(l4.data)
                if dns.qr == dpkt.dns.DNS_Q and dns.qd:
                    query = dns.qd[0].name + "."
            except (dpkt.UnpackError, IndexError, ValueError, UnicodeDecodeError):
                pass
        return PacketInfo(ts, src, dst, "DNS" if is_dns else "UDP", length, l4.sport, l4.dport,
                          dns_query=query, src_mac=mac)
    if isinstance(l4, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
        return PacketInfo(ts, src, dst, "ICMP", length, src_mac=mac)
    return PacketInfo(ts, src, dst, "OTHER", length, src_mac=mac)


def iter_pcap_fast(path: str):
    """Yield PacketInfo records from a .pcap or .pcapng file using dpkt."""
    import dpkt

    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        reader = dpkt.pcapng.Reader(f) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
        linktype = reader.datalink()
        for ts, buf in reader:
            info = _dpkt_info(float(ts), buf, linktype)
            if info is not None:
                yield info


def have_dpkt() -> bool:
    try:
        import dpkt  # noqa: F401
        return True
    except ImportError:
        return False


def read_pcap(analyzer: Analyzer, path: str, speed: float = 0, on_alert=None, progress=None):
    """Analyse a saved capture. With speed > 0 it is replayed in (sped-up) real time so the dashboard
    animates, e.g. speed=5 plays it five times faster than it was recorded. Uses the fast dpkt reader when it
    is installed, otherwise scapy. progress(packets) is called every 100,000 packets."""
    previous = None
    if have_dpkt():
        count = 0
        for info in iter_pcap_fast(path):
            if speed > 0:
                if previous is not None and info.ts > previous:
                    time.sleep(min((info.ts - previous) / speed, 2.0))
                previous = info.ts
            for alert in analyzer.process(info):
                if on_alert:
                    on_alert(alert)
            count += 1
            if progress and count % 100_000 == 0:
                progress(count)
    else:
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
