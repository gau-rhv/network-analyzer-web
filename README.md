# Network Analyzer

A network intrusion detection and traffic analysis tool I built for monitoring real-time network activity.

## What it does

- Captures live network packets using Scapy
- Shows real-time stats like packet counts, bandwidth usage, protocol distribution
- Detects suspicious activity (port scans, traffic spikes, invalid TCP flags)
- Filters packets by protocol, IP address, or port
- Exports data to JSON/CSV for further analysis

## Running it

You need sudo for packet capture:

```bash
sudo python3 -m network_analyzer --web
```

Then open http://127.0.0.1:5000

## Other commands

```bash
# Capture on specific interface
sudo python3 -m network_analyzer --capture -i en0

# Analyze a pcap file
python3 -m network_analyzer --pcap capture.pcap

# List interfaces
python3 -m network_analyzer --list-interfaces
```

## Dependencies

- Python 3.10+
- Flask, Flask-SocketIO
- Scapy

Install with:
```bash
pip install -r requirements.txt
```

## Project structure

```
network_analyzer/
├── __main__.py           # CLI
├── modules/
│   ├── packet_capture.py
│   ├── packet_filtering.py
│   ├── packet_analysis.py
│   ├── protocol_classification.py
│   ├── traffic_statistics.py
│   ├── alert_detection.py
│   ├── logging_reporting.py
│   └── visualization.py
└── web/
    ├── app.py
    ├── templates/index.html
    └── static/
```

## Author

Built by [@gau-rhv](https://github.com/gau-rhv)
