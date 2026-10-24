"""Reading the few unencrypted details at the start of connections, from raw bytes.

Most traffic is encrypted, but some details are still sent in the clear, and they say a lot:
- DNS replies: which name an address belongs to (e.g. 52.94.236.248 is netflix.com).
- The TLS ClientHello that opens every HTTPS connection: the website name (SNI) and the exact list of
  encryption options the program offers. That list is a fingerprint of the program (Chrome, Safari, curl, a
  piece of malware...), summarised as a JA4 fingerprint (https://github.com/FoxIO-LLC/ja4, BSD licence).
- DHCP requests: the name a device calls itself (e.g. "Nikhils-iPhone").

Only these headers are read - never page contents, passwords or messages, which stay encrypted. The parsers
work on plain bytes so the fast (dpkt) and slow (scapy) readers give identical results.
"""

from __future__ import annotations

import hashlib
import socket
import struct

# ---------------------------------------------------------------------------------------------- DNS


def _read_name(msg: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """A DNS name at pos (with compression pointers). Returns (name, position after it)."""
    labels = []
    while True:
        if pos >= len(msg) or depth > 20:
            raise ValueError("bad name")
        n = msg[pos]
        if n == 0:
            return ".".join(labels), pos + 1
        if n & 0xC0 == 0xC0:  # pointer to an earlier name
            if pos + 1 >= len(msg):
                raise ValueError("bad pointer")
            target = ((n & 0x3F) << 8) | msg[pos + 1]
            rest, _ = _read_name(msg, target, depth + 1)
            labels.append(rest)
            return ".".join(x for x in labels if x), pos + 2
        labels.append(msg[pos + 1:pos + 1 + n].decode("ascii", errors="replace"))
        pos += 1 + n


def dns_answers(msg: bytes) -> list[tuple[str, str, str]]:
    """(name asked for, address, name that actually holds the address) from a DNS reply. CNAME chains are
    followed back, so for 'metrics.shop.example -> CNAME shop.tracker.example -> 203.0.113.9' the result is
    ('metrics.shop.example', '203.0.113.9', 'shop.tracker.example'). A tracker hidden behind a site's own name
    this way is called CNAME cloaking."""
    try:
        if len(msg) < 12:
            return []
        _id, flags, qd, an = struct.unpack(">HHHH", msg[:8])
        if not flags & 0x8000 or an == 0:  # not a reply, or no answers
            return []
        pos = 12
        asked = None
        for _ in range(qd):
            name, pos = _read_name(msg, pos)
            asked = asked or name
            pos += 4
        alias: dict[str, str] = {}
        out = []
        for _ in range(min(an, 50)):
            name, pos = _read_name(msg, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
            pos += 10
            data = msg[pos:pos + rdlen]
            key = name.lower()
            if rtype == 5:  # CNAME
                target, _ = _read_name(msg, pos)
                alias[target.lower()] = alias.get(key, key)
            elif (rtype == 1 and rdlen == 4) or (rtype == 28 and rdlen == 16):
                ip = socket.inet_ntop(socket.AF_INET if rtype == 1 else socket.AF_INET6, data)
                out.append((alias.get(key, key), ip, key))
            pos += rdlen
        return out
    except (ValueError, struct.error, IndexError, OSError):
        return []


# ---------------------------------------------------------------------------------------------- DHCP


def dhcp_hostname(msg: bytes) -> str | None:
    """The host name (option 12) a device sends in a DHCP request."""
    if len(msg) < 240 or msg[236:240] != b"\x63\x82\x53\x63":
        return None
    pos = 240
    while pos + 1 < len(msg):
        code = msg[pos]
        if code == 255:
            break
        if code == 0:
            pos += 1
            continue
        n = msg[pos + 1]
        if code == 12:
            name = msg[pos + 2:pos + 2 + n].decode("utf-8", errors="replace").strip("\0 ")
            return name[:64] or None
        pos += 2 + n
    return None


# ---------------------------------------------------------------------------------------------- TLS


def _grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
             0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}


def client_hello_length(data: bytes) -> int | None:
    """If data starts a TLS handshake record holding a ClientHello, how many bytes the whole record needs."""
    if len(data) >= 6 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01:
        return 5 + struct.unpack(">H", data[3:5])[0]
    return None


def parse_client_hello(data: bytes, transport: str = "t") -> dict | None:
    """SNI, ALPN and JA4 fingerprint from a TLS record holding a ClientHello. None if it is not one or is cut off."""
    need = client_hello_length(data)
    if need is None or len(data) < need:
        return None
    try:
        body = data[9:need]  # after record header (5) and handshake header (4)
        legacy_version = struct.unpack(">H", body[0:2])[0]
        pos = 2 + 32  # version, random
        pos += 1 + body[pos]  # session id
        n = struct.unpack(">H", body[pos:pos + 2])[0]
        ciphers = [struct.unpack(">H", body[pos + 2 + i:pos + 4 + i])[0] for i in range(0, n, 2)]
        pos += 2 + n
        pos += 1 + body[pos]  # compression methods
        ext_end = pos + 2 + struct.unpack(">H", body[pos:pos + 2])[0] if pos + 2 <= len(body) else pos
        pos += 2
        extensions, sni, alpn, sig_algs, versions = [], None, [], [], []
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack(">HH", body[pos:pos + 4])
            edata = body[pos + 4:pos + 4 + elen]
            extensions.append(etype)
            if etype == 0x0000 and len(edata) >= 5 and edata[2] == 0:  # server_name, host_name entry
                k = struct.unpack(">H", edata[3:5])[0]
                sni = edata[5:5 + k].decode("ascii", errors="replace").lower() or None
            elif etype == 0x0010 and len(edata) >= 2:  # ALPN
                p = 2
                while p < len(edata):
                    k = edata[p]
                    alpn.append(edata[p + 1:p + 1 + k])
                    p += 1 + k
            elif etype == 0x000D and len(edata) >= 2:  # signature algorithms (order kept)
                k = struct.unpack(">H", edata[:2])[0]
                sig_algs = [struct.unpack(">H", edata[2 + i:4 + i])[0] for i in range(0, k, 2)]
            elif etype == 0x002B and edata:  # supported versions
                versions = [struct.unpack(">H", edata[1 + i:3 + i])[0] for i in range(0, edata[0], 2)]
            pos += 4 + elen
    except (struct.error, IndexError):
        return None

    ciphers = [c for c in ciphers if not _grease(c)]
    extensions = [e for e in extensions if not _grease(e)]
    versions = [v for v in versions if not _grease(v)]
    version = _VERSIONS.get(max(versions) if versions else legacy_version, "00")
    first_alpn = alpn[0] if alpn else b""
    if not first_alpn:
        alpn_code = "00"
    elif chr(first_alpn[0]).isalnum() and chr(first_alpn[-1]).isalnum():
        alpn_code = chr(first_alpn[0]) + chr(first_alpn[-1])
    else:
        alpn_code = f"{first_alpn[0]:02x}"[0] + f"{first_alpn[-1]:02x}"[1]
    part_a = (f"{transport}{version}{'d' if sni else 'i'}{min(len(ciphers), 99):02d}"
              f"{min(len(extensions), 99):02d}{alpn_code}")

    def h(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"

    part_b = h(",".join(sorted(f"{c:04x}" for c in ciphers)))
    ext_list = ",".join(sorted(f"{e:04x}" for e in extensions if e not in (0x0000, 0x0010)))
    if sig_algs and ext_list:
        ext_list += "_" + ",".join(f"{s:04x}" for s in sig_algs)
    part_c = h(ext_list)
    return {"sni": sni, "alpn": first_alpn.decode("ascii", errors="replace") or None,
            "ja4": f"{part_a}_{part_b}_{part_c}"}


class TLSReassembler:
    """Joins a ClientHello split over several TCP packets. Modern browsers send hellos bigger than one packet
    (post-quantum key exchange), so reading only the first packet would miss most of them. Only the first few
    packets of each connection are kept, and only until the hello is complete."""

    def __init__(self, max_flows: int = 4096):
        self.pending: dict[tuple, bytearray] = {}
        self.max_flows = max_flows

    def feed(self, flow: tuple, payload: bytes) -> dict | None:
        if not payload:
            return None
        buf = self.pending.get(flow)
        if buf is None:
            need = client_hello_length(payload)
            if need is None:
                return None
            if len(payload) >= need:
                return parse_client_hello(payload)
            if len(self.pending) >= self.max_flows:
                self.pending.pop(next(iter(self.pending)))
            self.pending[flow] = bytearray(payload)
            return None
        buf.extend(payload)
        need = client_hello_length(bytes(buf[:6])) or 0
        if len(buf) >= need or len(buf) > 16384:
            del self.pending[flow]
            return parse_client_hello(bytes(buf))
        return None


# ---------------------------------------------------------------------------------------------- building (tests, demo)

CHROME_CIPHERS = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                  0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
CHROME_EXTENSIONS = [0x1A1A, 0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012,
                     0x0033, 0x002D, 0x002B, 0x001B, 0x4469, 0x2A2A, 0x0015]
CHROME_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def build_client_hello(sni: str | None, ciphers=None, extensions=None, sig_algs=None, alpn=(b"h2", b"http/1.1"),
                       padding: int = 0) -> bytes:
    """A syntactically valid TLS 1.3 ClientHello (Chrome-like by default). Used to make test and demo captures."""
    ciphers = CHROME_CIPHERS if ciphers is None else ciphers
    extensions = CHROME_EXTENSIONS if extensions is None else extensions
    sig_algs = CHROME_SIG_ALGS if sig_algs is None else sig_algs
    ext_bytes = b""
    for e in extensions:
        if e == 0x0000:
            if not sni:
                continue
            name = sni.encode()
            data = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
        elif e == 0x0010:
            items = b"".join(bytes([len(a)]) + a for a in alpn)
            data = struct.pack(">H", len(items)) + items
        elif e == 0x000D:
            data = struct.pack(">H", 2 * len(sig_algs)) + b"".join(struct.pack(">H", s) for s in sig_algs)
        elif e == 0x002B:
            data = bytes([6]) + struct.pack(">HHH", 0x3A3A, 0x0304, 0x0303)
        elif e == 0x0015:
            data = b"\0" * padding
        else:
            data = b""
        ext_bytes += struct.pack(">HH", e, len(data)) + data
    body = (struct.pack(">H", 0x0303) + b"\x11" * 32 + b"\x20" + b"\x22" * 32
            + struct.pack(">H", 2 * len(ciphers)) + b"".join(struct.pack(">H", c) for c in ciphers)
            + b"\x01\x00" + struct.pack(">H", len(ext_bytes)) + ext_bytes)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
