"""Finding every device on your home network at once (the "Find all devices" button).

The monitor normally only listens, so a phone in standby or an idle TV stays invisible until it sends something.
Device-finder apps such as Fing instead ask every address on the network "who has this address?" (an ARP
request), and every device answers at once. This module does the same:

- Only your own local network is asked, the subnet of the interface being watched (for example
  192.168.1.0/24); anything that is not a private home/office range is refused, and at most 1,024 addresses.
- An ARP request is the ordinary message every device sends before talking to a neighbour. Nothing is sent to
  the internet and no ports are probed.
- It needs administrator rights, like live capture.
"""

from __future__ import annotations

import ipaddress
import time

from .analyzer import PacketInfo

MAX_ADDRESSES = 1024


def local_network(iface: str | None = None) -> ipaddress.IPv4Network | None:
    """The private IPv4 subnet of an interface, from the system's routing table."""
    from scapy.all import conf, get_if_addr

    iface = iface or conf.iface
    my_ip = get_if_addr(iface)
    if not my_ip or my_ip == "0.0.0.0":
        return None
    best = None
    for net, mask, _gw, route_iface, addr, _metric in conf.route.routes:
        if str(route_iface) != str(iface) or addr != my_ip or mask in (0, 0xFFFFFFFF):
            continue
        prefix = bin(mask).count("1")
        candidate = ipaddress.ip_network(f"{ipaddress.IPv4Address(net)}/{prefix}", strict=False)
        if ipaddress.ip_address(my_ip) in candidate and (best is None or candidate.prefixlen > best.prefixlen):
            best = candidate
    if best is None:
        best = ipaddress.ip_network(f"{my_ip}/24", strict=False)
    return best


def safe_range(network: ipaddress.IPv4Network, my_ip: str | None = None) -> ipaddress.IPv4Network:
    """Refuse anything but a private range, and shrink very large ones to the /24 around this computer."""
    if not network.is_private or network.is_loopback or network.is_link_local:
        raise ValueError(f"{network} is not a private home or office network, so it will not be scanned")
    if network.num_addresses > MAX_ADDRESSES:
        centre = my_ip or str(network.network_address)
        network = ipaddress.ip_network(f"{centre}/24", strict=False)
    return network


def arp_sweep(iface: str | None = None, timeout: float = 2.0, sender=None) -> dict:
    """Ask every address on the local network who is there. Returns {"network", "devices": [(ip, mac)]}."""
    from scapy.all import ARP, Ether, conf, get_if_addr, srp

    iface = iface or conf.iface
    network = safe_range(local_network(iface), get_if_addr(iface))
    send = sender or (lambda pkt: srp(pkt, iface=iface, timeout=timeout, verbose=False)[0])
    answered = send(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)))
    found = sorted({(reply.psrc, reply.hwsrc.lower()) for _sent, reply in answered},
                   key=lambda x: ipaddress.ip_address(x[0]))
    return {"network": str(network), "devices": found}


def feed(analyzer, found: list) -> int:
    """Give the answers to the analyser as ARP packets, so the devices appear even before they speak."""
    now = time.time()
    for ip, mac in found:
        analyzer.process(PacketInfo(now, ip, "0.0.0.0", "ARP", 42, src_mac=mac))
    return len(found)
