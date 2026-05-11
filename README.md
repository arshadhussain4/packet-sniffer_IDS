# Packet Sniffer / IDS 
A Python-based network packet sniffer with a live GUI, threat detection, and automatic logging to CSV and alerts file.

Built as part of a cybersecurity project to understand how data flows through a network, how protocols work, and how basic intrusion detection systems (IDS) operate.

---

## Features

- Live packet capture using Scapy
- GUI interface with Start / Stop controls
- Detects suspicious ports (Metasploit, RDP, Telnet, Backdoor, etc.)
- Port scan detection — flags IPs hitting 5+ different ports
- DNS query monitoring — shows which websites are being accessed
- Hostname resolution — translates IPs to readable names
- Logs all packets to `packets.csv`
- Logs all alerts to `alerts.txt`
- Packet limit (default: 1000) to prevent runaway capture

---

## Requirements

- Python 3.8+
- Windows: [Npcap](https://npcap.com/) must be installed (tick WinPcap-compatible mode)
- Linux/Mac: run with `sudo`

---

## Installation

```bash
git clone https://github.com/arshadhussain4/packet-sniffer_IDS.git
cd packet-sniffer_IDS
pip install -r requirements.txt
```

---

## Usage

Click **Start Sniffing** in the GUI. Packets appear live in the log window. The tool stops automatically after 1000 packets or when you click **Stop Sniffing**.

---

## Output Files

| File | Contents |
|------|----------|
| `packets.csv` | Every captured packet with src/dst IP, protocol, ports, hostname, DNS query, payload preview, alert |
| `alerts.txt` | Only suspicious events — bad ports and port scans with timestamps |

---

## Suspicious Ports Monitored

| Port | Service | Why |
|------|---------|-----|
| 22 | SSH | Unexpected remote access |
| 23 | Telnet | Unencrypted, obsolete |
| 3389 | RDP | Windows remote — common attack target |
| 4444 | Metasploit | Default hacking framework port |
| 6667 | IRC | Botnet command & control |
| 31337 | Backdoor | Classic malware port |

---

## Project Structure

```
packet-sniffer/
├── packet_sniffer.py   # Main application
├── requirements.txt    # Python dependencies
├── .gitignore          # Files excluded from git
├── LICENSE             # MIT License
├── packets.csv         # Generated on first run (not tracked by git)
└── alerts.txt          # Generated on first run (not tracked by git)
```

---

## Ethical Notice

This tool is for **educational and authorized use only**. Only run it on your own network or with explicit permission. Capturing packets on networks you do not own is illegal.

---

## License

MIT License — see [LICENSE](LICENSE)
