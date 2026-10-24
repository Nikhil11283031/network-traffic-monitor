"""Create samples/demo.pcap: 90 seconds of simulated home-network traffic with some attacks mixed in.

Nothing is sent on a network - packets are only built in memory and written to a file, so the
monitor can be demonstrated without capturing anyone's real traffic.

Timeline (seconds from the start):
    0-90   normal browsing, streaming and DNS from a laptop, phone and smart TV
    40     an unknown device (192.168.1.99) joins the network
    45-50  it port-scans the laptop
    55     it tries to log in to the router with Telnet
    57     it sends fake ARP replies claiming to be the router (ARP spoofing / man-in-the-middle)
    58-64  it tries to guess the laptop's SSH password (30 login attempts)
    3-83   the smart TV quietly "calls home" to a server every 8 seconds (beaconing)
    60-66  the smart TV looks up random-looking names (DNS tunnelling)
    70-78  the phone uploads 6 MB to an outside server (possible data theft)
    68     the smart TV opens an encrypted connection with an unknown program and no website name (malware)

Privacy X-ray material: every device looks names up (with DNS replies) and opens HTTPS with the website name
(SNI). The TV reports viewing data to samsungacr.com and ads to samsungads.com, the phone talks to Facebook and
Firebase analytics, and the laptop visits a shop whose "metrics" name secretly points to a tracker (CNAME
cloaking). The phone announces its name in a DHCP request.
"""

import random
import string
import sys
from pathlib import Path

from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

sys.path.insert(0, str(Path(__file__).resolve().parent))
from netmon.payload import build_client_hello  # noqa: E402

START = 1_792_000_000.0  # a fixed start time so the file is the same every time
ROUTER = ("192.168.1.1", "aa:bb:cc:00:00:01")
LAPTOP = ("192.168.1.10", "aa:bb:cc:00:00:10")
PHONE = ("192.168.1.11", "aa:bb:cc:00:00:11")
TV = ("192.168.1.12", "aa:bb:cc:00:00:12")
INTRUDER = ("192.168.1.99", "de:ad:be:ef:00:99")
SITES = {"google.com": "142.250.66.78", "github.com": "20.248.137.48", "youtube.com": "142.250.70.238",
         "uow.edu.au": "130.130.68.5", "netflix.com": "52.94.236.248", "apple.com": "17.253.144.10"}
# Extra sites each device uses, for the Privacy X-ray (documentation addresses, not real servers).
DEVICE_SITES = {
    "192.168.1.10": {"metrics.shopnow.example": "198.51.100.41"},  # CNAME-cloaked tracker, see below
    "192.168.1.11": {"graph.facebook.com": "198.51.100.42", "app-measurement.com": "198.51.100.43"},
    "192.168.1.12": {"log-config.samsungacr.com": "198.51.100.44", "config.samsungads.com": "198.51.100.45"},
}
CLOAK = {"metrics.shopnow.example": "shopnow.eulerian.net"}
# The "malware" on the TV: an old-style TLS client with few options and no website name.
MALWARE_HELLO = build_client_hello(None, ciphers=[0xC02F, 0xC030, 0x009E, 0x009F, 0xC013, 0xC014, 0x002F, 0x0035],
                                   extensions=[0x000A, 0x000B, 0x000D, 0x0017, 0xFF01],
                                   sig_algs=[0x0401, 0x0501, 0x0601], alpn=())


def pkt(t, src, dst, layer4, payload=b"", dst_mac="aa:bb:cc:00:00:01"):
    p = Ether(src=src[1], dst=dst_mac) / IP(src=src[0], dst=dst) / layer4
    if payload:
        p = p / Raw(payload)
    p.time = START + t
    return p


def main(out="samples/demo.pcap"):
    rng = random.Random(927)
    packets = []

    # Normal traffic: each device looks up a site, gets the answer, connects with HTTPS (naming the site in the
    # ClientHello) and exchanges some data.
    for second in range(90):
        for device in (LAPTOP, PHONE, TV):
            if rng.random() < 0.5:
                sites = list(SITES.items()) + list(DEVICE_SITES[device[0]].items())
                site, ip = rng.choice(sites)
                t = second + rng.random()
                sport = rng.randint(40000, 60000)
                packets.append(pkt(t, device, ROUTER[0], UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=site))))
                if site in CLOAK:
                    answers = [DNSRR(rrname=site, type="CNAME", rdata=CLOAK[site]),
                               DNSRR(rrname=CLOAK[site], type="A", rdata=ip)]
                else:
                    answers = [DNSRR(rrname=site, type="A", rdata=ip)]
                reply = Ether(src=ROUTER[1], dst=device[1]) / IP(src=ROUTER[0], dst=device[0]) / \
                    UDP(sport=53, dport=sport) / DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname=site), an=answers)
                reply.time = START + t + 0.01
                packets.append(reply)
                packets.append(pkt(t + 0.02, device, ip, TCP(sport=sport, dport=443, flags="S")))
                packets.append(pkt(t + 0.04, device, ip, TCP(sport=sport, dport=443, flags="PA"),
                                   build_client_hello(site)))
                for i in range(rng.randint(3, 8)):
                    back = Ether(src="aa:bb:cc:00:00:01", dst=device[1]) / IP(src=ip, dst=device[0]) / \
                        TCP(sport=443, dport=sport, flags="A") / Raw(b"x" * rng.randint(600, 1400))
                    back.time = START + t + 0.05 + i * 0.03
                    packets.append(back)
                    packets.append(pkt(t + 0.06 + i * 0.03, device, ip, TCP(sport=sport, dport=443, flags="A")))

    # 2 s: the phone asks the router for its address and gives its name (DHCP).
    dhcp = Ether(src=PHONE[1], dst="ff:ff:ff:ff:ff:ff") / IP(src=PHONE[0], dst="255.255.255.255") / \
        UDP(sport=68, dport=67) / BOOTP(chaddr=bytes.fromhex("aabbcc000011")) / \
        DHCP(options=[("message-type", "request"), ("hostname", b"Nikhils-iPhone"), "end"])
    dhcp.time = START + 2.0
    packets.append(dhcp)

    # 68 s: a program on the TV that was never used before opens an encrypted connection to a bare address,
    # without naming a website.
    packets.append(pkt(68.0, TV, "198.51.100.66", TCP(sport=47000, dport=443, flags="S")))
    packets.append(pkt(68.05, TV, "198.51.100.66", TCP(sport=47000, dport=443, flags="PA"), MALWARE_HELLO))

    # 1 s: the router announces its address (ARP), so its real MAC address is known.
    arp = Ether(src=ROUTER[1], dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=ROUTER[0], hwsrc=ROUTER[1],
                                                              pdst=ROUTER[0], hwdst="ff:ff:ff:ff:ff:ff")
    arp.time = START + 1.0
    packets.append(arp)

    # 3-83 s: the TV connects to the same outside server every 8 seconds (malware beacon).
    for i in range(11):
        t = 3.0 + i * 8 + rng.uniform(-0.3, 0.3)
        packets.append(pkt(t, TV, "198.51.100.23", TCP(sport=45000 + i, dport=443, flags="S")))
        packets.append(pkt(t + 0.05, TV, "198.51.100.23", TCP(sport=45000 + i, dport=443, flags="A"), b"b" * 90))

    # 40 s: an unknown device appears, then port-scans the laptop (ports 1-100 over five seconds).
    packets.append(pkt(40.0, INTRUDER, ROUTER[0], UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="router.local"))))
    for i, port in enumerate(range(1, 101)):
        packets.append(pkt(45 + i * 0.05, INTRUDER, LAPTOP[0], TCP(sport=61000, dport=port, flags="S"),
                           dst_mac=LAPTOP[1]))

    # 55 s: it tries Telnet on the router.
    packets.append(pkt(55.0, INTRUDER, ROUTER[0], TCP(sport=61001, dport=23, flags="S")))

    # 57 s: it claims to be the router (ARP spoofing) to put itself in the middle of everyone's traffic.
    for i in range(3):
        spoof = Ether(src=INTRUDER[1], dst=LAPTOP[1]) / ARP(op=2, psrc=ROUTER[0], hwsrc=INTRUDER[1],
                                                            pdst=LAPTOP[0], hwdst=LAPTOP[1])
        spoof.time = START + 57.0 + i * 0.5
        packets.append(spoof)

    # 58-64 s: it tries to guess the laptop's SSH password.
    for i in range(30):
        packets.append(pkt(58 + i * 0.2, INTRUDER, LAPTOP[0], TCP(sport=62000 + i, dport=22, flags="S"),
                           dst_mac=LAPTOP[1]))

    # 60-66 s: the TV sends data hidden in DNS names.
    for i in range(12):
        label = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(48))
        packets.append(pkt(60 + i * 0.5, TV, ROUTER[0],
                           UDP(sport=50000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"{label}.cdn-sync.example"))))

    # 70-78 s: the phone uploads about 6 MB to an unknown server.
    for i in range(4300):
        packets.append(pkt(70 + i * (8 / 4300), PHONE, "203.0.113.50", TCP(sport=52000, dport=443, flags="A"),
                           payload=b"u" * 1400))

    packets.sort(key=lambda p: p.time)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(out, packets)
    print(f"Wrote {len(packets):,} packets to {out}")


if __name__ == "__main__":
    main(*sys.argv[1:])
