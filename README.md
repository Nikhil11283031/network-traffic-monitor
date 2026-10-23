# Network Traffic Monitor

A Python tool that watches network traffic, detects suspicious activity and shows it on a live web dashboard.
It can capture live traffic from your own computer's network interface or analyse a saved `.pcap` capture file
(for example one recorded with Wireshark).

![Dashboard](docs/dashboard.png)

## What it detects

| Alert | Severity | How it is detected |
| --- | --- | --- |
| **Port scan** | High | One host tries 15+ different ports on another host within 10 seconds (counts connection attempts only, so normal replies are ignored). |
| **SYN flood** | High | 200+ connection attempts to one host within 5 seconds - a sign of a denial-of-service attack. |
| **Risky port** | Medium | A connection to a service that is unsafe or often abused: FTP (21), Telnet (23), SMB (445), MS SQL (1433), RDP (3389), 4444 (common backdoor), VNC (5900), IRC (6667). |
| **High traffic** | Medium | One host sends 5 MB+ within 10 seconds - a large upload could be data being stolen. |
| **Suspicious DNS** | Medium | A DNS lookup with a very long (40+ characters) or random-looking name, measured with Shannon entropy. Malware uses this to hide data in DNS (DNS tunnelling) or to find its servers. |
| **New device** | Low | A device that was not on the local network during the first 30 seconds appears. |

Repeated alerts for the same thing are grouped (one alert per minute), so the list stays readable. All limits
are in `Config` in `netmon/analyzer.py` and can be changed.

The dashboard also shows packets per second, protocols, the hosts sending and receiving the most data, the
ports being contacted (risky ones in red), DNS lookups by domain, and every device seen on the local network.

## AI security analyst agent

The dashboard has an **AI security analyst**: an agent built on Claude (Anthropic API) that investigates the
traffic by itself and writes an incident report, or answers questions such as *"Is 192.168.1.12 infected?"*.

![AI analyst](docs/agent.png)

It works as a **tool-using agent loop** (`netmon/agent.py`):

1. The agent receives the request and a list of tools it may call.
2. Claude decides which tool it needs and the program runs it, for example `get_overview`, then
   `get_host_activity("192.168.1.99")`, then `get_response_playbook("Port scan")`.
3. The result goes back to Claude, which decides on the next step. This repeats (up to 10 rounds) until it has
   enough evidence.
4. It writes a report: summary and risk level, one section per incident with evidence, the likely explanation
   (including innocent ones) and recommended actions. The dashboard shows each tool call it made.

| Tool | What it returns |
| --- | --- |
| `get_overview` | Totals, protocols, top talkers, ports, DNS domains, devices, alert counts |
| `list_alerts` | Alerts, filtered by severity or type |
| `get_host_activity` | One IP: data sent/received, who it talked to, ports, DNS lookups, MAC, its alerts |
| `get_dns_lookups` | DNS names looked up by a host, or the top domains |
| `lookup_port` | The service on a port and whether it is risky |
| `get_response_playbook` | Standard response steps for an alert type |

**Safety design**

- **Read-only tools.** The agent can look but cannot block traffic or change anything, so a wrong answer
  cannot cause harm. A person decides what to do.
- **Prompt-injection defence.** Packet contents (DNS names especially) are controlled by whoever sends the
  packets. An attacker could look up a name like `ignore-previous-instructions...`. The system prompt tells the
  model to treat all tool output as untrusted data, and long strings are cut to 120 characters.
- **Fallback.** Without an API key, or if the API cannot be reached, a built-in **offline rule-based analyst**
  writes the report from the alerts and playbooks, so the tool always works.

**Turning on Claude**

```bash
export ANTHROPIC_API_KEY=sk-ant-...          # from https://console.anthropic.com
export NETMON_MODEL=claude-sonnet-5-5        # optional, this is the default
python3 -m netmon pcap samples/demo.pcap --speed 5
```

Console only: `python3 -m netmon pcap samples/demo.pcap --no-web --investigate`.

## Setup

Needs Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running it

**1. Demo with the sample capture (no admin rights needed)**

```bash
python3 make_sample_pcap.py                         # creates samples/demo.pcap
python3 -m netmon pcap samples/demo.pcap --speed 5  # replays it 5x faster
```

Open <http://127.0.0.1:5050>. Over about 20 seconds you will see normal traffic, then an unknown device join
the network, port-scan a laptop, try Telnet on the router, a smart TV leak data through DNS, and a phone upload
6 MB to an outside server. Each one appears as an alert.

**2. Watch your own network live**

Capturing packets needs administrator rights:

```bash
sudo .venv/bin/python -m netmon live                 # default interface
sudo .venv/bin/python -m netmon live --iface en0     # en0 is usually Wi-Fi on a Mac
sudo .venv/bin/python -m netmon live --filter "tcp or udp port 53"
```

To try the detection safely on your own machine, scan your own computer from another terminal, e.g.
`nmap -p 1-100 127.0.0.1` with `--iface lo0` (Mac) or `--iface lo` (Linux).

**3. Analyse a Wireshark capture**

```bash
python3 -m netmon pcap mycapture.pcap                # instant analysis + dashboard
python3 -m netmon pcap mycapture.pcap --no-web --report report.json   # console only, save a JSON report
```

Other options: `--port 5051` to change the dashboard port, `--no-web` for console-only output.

## How it works

```
 network interface ──► scapy sniff()  ─┐
                                       ├─► to_packet_info() ─► Analyzer.process() ─► alerts + statistics
 .pcap file ────────► scapy PcapReader ┘          (capture.py)        (analyzer.py)          │
                                                                                             ▼
                                                     browser ◄── /api/snapshot (JSON) ◄── Flask (web.py)
                                                        │                                    ▲
                                                        └─► /api/agent ─► AI analyst ─► tools ┘ (read-only)
                                                                         (agent.py) ◄─► Claude API
```

- `netmon/capture.py` reads packets with **scapy** and turns each one into a small `PacketInfo` record
  (time, addresses, protocol, ports, TCP flags, DNS name, MAC address).
- `netmon/analyzer.py` keeps running statistics and applies the detection rules using **sliding time windows**
  based on each packet's own timestamp, so a saved capture gives exactly the same results as watching live.
- `netmon/web.py` serves the dashboard; the page asks for a fresh snapshot every two seconds.
- `netmon/agent.py` is the AI analyst; it reads the same analyser through read-only tools.
- Capture runs in a background thread; a lock keeps the statistics consistent while the dashboard reads them.

## Tests

```bash
python3 -m pytest
```

20 tests cover each detection rule, false-positive checks (normal browsing, slow connections, replies, ordinary
long domain names), configurable thresholds, an end-to-end run over the sample capture, and the AI agent: the
tool-calling loop (with a scripted fake Claude client, so no API key is needed), the step limit, the offline
fallback, bad tool input, clipping of long attacker-controlled strings, and the web endpoints.

## Limitations and ideas

- Encrypted traffic (HTTPS) is not decrypted; the monitor looks at who talks to whom, how much and when.
- Rules are thresholds, so a slow scan spread over minutes is not caught; a learning baseline per device
  would be a good next step.
- Alerts could be sent by email or Slack, or saved to a database for history.

## Ethics

Only monitor networks you own or have written permission to monitor. Capturing other people's traffic without
permission is illegal in Australia and many other countries. The sample capture is fully simulated.
