"""Safe attack lab: record real packets while running harmless "attacks" against your own computer, and write
the answer key, so the monitor can be benchmarked on real traffic without downloading anything.

    python3 labs/self_lab.py            # about 4 minutes; asks for your password once (for tcpdump)
    python3 -m netmon benchmark lab/lab.pcap --truth lab/lab-truth.json --ml-learn 50

Everything stays on your computer:
- The recording is taken on the loopback interface (lo0 on macOS, lo on Linux): the private channel a computer
  uses to talk to itself. Nothing is recorded from your Wi-Fi, and no attack traffic leaves the computer.
- Every "attack" targets this computer's own address only:
    port scan     knocks once on ports 1-300 (connections open and close immediately, nothing is sent)
    SSH guessing  30 connection attempts to port 22; no username or password is ever sent, and if Remote Login
                  is off (the default) they are simply refused
    DNS tunnel    15 lookups of random-looking names sent to port 53 of this computer, where nothing listens
    big upload    8 MB of zeros sent to a temporary listener started by this script, then thrown away
- tcpdump (built into macOS and Linux) needs administrator rights to record, so the script runs it with sudo
  and stops it automatically when the lab ends.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import shutil
import socket
import string
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path


def own_address() -> str:
    """This computer's address on its network (no packet is sent to find it). Falls back to 127.0.0.1."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # documentation address: connect() on UDP only picks a route
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def running(pid: str) -> bool:
    """Whether a process is still alive (ps works for root-owned processes too)."""
    return subprocess.run(["ps", "-p", pid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def say(text: str):
    print(f"[{time.strftime('%H:%M:%S')}] {text}", flush=True)


def port_scan(ip: str):
    for port in range(1, 301):
        s = socket.socket()
        s.settimeout(0.05)
        try:
            s.connect((ip, port))
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(0.005)


def ssh_guessing(ip: str):
    for _ in range(30):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect((ip, 22))  # connect and close: no username or password is sent
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(0.3)


def dns_tunnel(ip: str):
    rng = random.Random()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(15):
        label = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(45))
        qname = b"".join(bytes([len(part)]) + part.encode() for part in [label, "lab-exfil", "example"]) + b"\0"
        query = struct.pack(">HHHHHH", rng.randint(0, 65535), 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
        try:
            sock.sendto(query, (ip, 53))  # nothing listens there; the packet is simply dropped
        except OSError:
            pass
        time.sleep(0.5)
    sock.close()


def big_upload(ip: str, megabytes: int = 8):
    server = socket.socket()
    server.bind((ip, 0))
    server.listen(1)
    port = server.getsockname()[1]

    def sink():
        conn, _ = server.accept()
        while conn.recv(1 << 16):
            pass
        conn.close()

    t = threading.Thread(target=sink, daemon=True)
    t.start()
    client = socket.create_connection((ip, port))
    chunk = b"\0" * (1 << 16)
    for _ in range(megabytes * 16):
        client.sendall(chunk)
    client.close()
    t.join(timeout=10)
    server.close()


ATTACKS = [
    ("Port scan of this computer (ports 1-300)", port_scan, ["Port scan"]),
    ("SSH password guessing (30 attempts, no passwords sent)", ssh_guessing, ["Brute force"]),
    ("DNS tunnelling (random-looking names)", dns_tunnel, ["Suspicious DNS"]),
    ("8 MB upload (data theft)", big_upload, ["High traffic"]),
]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default="lab", help="folder for lab.pcap and lab-truth.json (default lab/)")
    parser.add_argument("--iface", default="lo0" if platform.system() == "Darwin" else "lo")
    parser.add_argument("--baseline", type=int, default=60, help="seconds of quiet traffic first (default 60)")
    parser.add_argument("--gap", type=int, default=30, help="seconds between attacks (default 30)")
    parser.add_argument("--no-sudo", action="store_true", help="run tcpdump directly (when already root)")
    args = parser.parse_args(argv)

    if not shutil.which("tcpdump"):
        sys.exit("tcpdump was not found. It is built into macOS; on Linux install it (sudo apt install tcpdump).")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    pcap, truth_path = out / "lab.pcap", out / "lab-truth.json"
    ip = own_address()
    total = args.baseline + len(ATTACKS) * args.gap + 20
    print(f"Safe attack lab: recording {args.iface} for about {total // 60} min {total % 60} s. Target: this "
          f"computer only ({ip}).\nNothing is sent to other devices or the internet.\n")

    # tcpdump is started in the background by a short-lived shell, so sudo exits at once. (If sudo stayed running
    # in front, it would switch the Terminal to raw mode and every printed line would drift to the right.)
    log = out / "tcpdump.log"
    shell = f"tcpdump -i {args.iface} -n -U -s 256 -w '{pcap}' >/dev/null 2>'{log}' & echo $!"
    prefix = []
    if not args.no_sudo and os.geteuid() != 0:
        print("tcpdump needs administrator rights to record - enter your Mac password if asked.")
        subprocess.run(["sudo", "-v"], check=True)  # ask for the password now, not in the middle of the lab
        prefix = ["sudo"]
    started = subprocess.run(prefix + ["sh", "-c", shell], capture_output=True, text=True)
    pid = started.stdout.strip()
    time.sleep(2)
    if not pid.isdigit() or not running(pid):
        sys.exit("tcpdump could not start: " + (log.read_text(errors="replace") if log.exists() else started.stderr))

    episodes = []
    try:
        say(f"Recording normal traffic for {args.baseline} s so the detectors learn what is normal...")
        time.sleep(args.baseline)
        for name, attack, expected in ATTACKS:
            say(f"Attack: {name}")
            start = time.time()
            attack(ip)
            end = time.time()
            episodes.append({"name": name, "start": round(start, 3), "end": round(end, 3), "attackers": [ip],
                             "victims": [ip], "expected": expected})
            say(f"  done in {end - start:.1f} s. Quiet for {args.gap} s...")
            time.sleep(args.gap)
    finally:
        time.sleep(2)
        subprocess.run(prefix + ["kill", "-INT", pid], check=False)  # tcpdump saves the file and exits
        for _ in range(50):
            if not running(pid):
                break
            time.sleep(0.2)
    if prefix and pcap.exists():
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(pcap), str(log)], check=False)

    truth = {"description": f"Self lab on {platform.node()} ({ip}), interface {args.iface}. Every attack targeted "
                            "this computer only.", "episodes": episodes}
    truth_path.write_text(json.dumps(truth, indent=2) + "\n")
    print(f"\nSaved the recording to {pcap} and the answer key to {truth_path}.")
    print(f"Next: python3 -m netmon benchmark {pcap} --truth {truth_path} --ml-learn {max(args.baseline - 10, 20)}")


if __name__ == "__main__":
    main()
