# 🔒 Network Analyzer

A real-time network intrusion detection and traffic analysis system built with Python, Flask, and Scapy.

![Dashboard](https://img.shields.io/badge/Dashboard-Modern%20UI-6366f1)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## ✨ Features

### 📊 Real-time Dashboard
- Live packet capture and analysis
- Protocol distribution charts
- Packet rate timeline
- Top source/destination IP tracking
- Traffic statistics (packets, bytes, bandwidth)

### 🔍 Packet Filtering
- Filter by protocol (TCP, UDP, HTTP, HTTPS, DNS, ICMP)
- Filter by source/destination IP
- Filter by port number

### 🚨 Alert Detection
- Port scan detection
- Traffic spike detection
- Invalid TCP flags detection
- ICMP anomaly detection

### 📋 Logs & Reporting
- In-browser log viewer
- Export to JSON/CSV
- Generate HTML reports

### 🎨 Modern UI
- Glassmorphism design
- Dark theme
- Smooth animations
- Responsive layout

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/network-analyzer.git
cd network-analyzer

# Install dependencies
pip install -r requirements.txt
```

## 📦 Requirements

- Python 3.10+
- Flask
- Flask-SocketIO
- Scapy

## 🖥️ Usage

### Start the Web Dashboard

```bash
# Requires sudo for packet capture privileges
sudo python3 -m network_analyzer --web
```

Open **http://127.0.0.1:5000** in your browser.

### Command Line Options

```bash
# Capture on specific interface
sudo python3 -m network_analyzer --capture -i en0

# Analyze PCAP file
python3 -m network_analyzer --pcap capture.pcap

# List available interfaces
python3 -m network_analyzer --list-interfaces

# Custom host/port for web UI
sudo python3 -m network_analyzer --web --host 0.0.0.0 --port 8080
```

## 📁 Project Structure

```
network_analyzer/
├── __main__.py              # CLI entry point
├── modules/
│   ├── packet_capture.py    # Live packet capturing
│   ├── packet_filtering.py  # Packet filters
│   ├── packet_analysis.py   # Packet dissection
│   ├── protocol_classification.py  # Protocol detection
│   ├── traffic_statistics.py       # Bandwidth & stats
│   ├── alert_detection.py   # Security alerts
│   ├── logging_reporting.py # Export & reports
│   └── visualization.py     # Chart data helpers
└── web/
    ├── app.py               # Flask web server
    ├── templates/
    │   └── index.html       # Dashboard UI
    └── static/
        ├── css/style.css    # Glassmorphism styles
        └── js/app.js        # Real-time updates
```

## 📸 Screenshots

### Dashboard
Real-time stats with protocol distribution and packet rate charts.

### Packet Filtering
Filter captured packets by protocol, IP, or port.

### Alerts Panel
Security alerts with severity levels (Critical, Warning, Info).

### Logs Viewer
View and export logs directly from the browser.

## 🔧 Modules

| Module | Description |
|--------|-------------|
| Packet Capture | Live network sniffing with Scapy |
| Packet Filtering | Filter by protocol, IP, port |
| Packet Analysis | Extract headers, flags, payload |
| Protocol Classification | Identify HTTP, DNS, SSH, etc. |
| Traffic Statistics | Bandwidth, packet counts, rates |
| Visualization | Charts and timeline data |
| Alert Detection | Intrusion detection rules |
| Logging & Reporting | JSON, CSV, HTML exports |

## ⚠️ Requirements Note

**Root/Admin privileges are required** for live packet capture on most systems.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 👨‍💻 Author

Built with ❤️ for network analysis and security monitoring.
