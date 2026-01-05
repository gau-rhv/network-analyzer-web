# Network Intrusion Detection System - Web UI

A comprehensive network monitoring tool with a beautiful, real-time web dashboard.

## 🚀 Quick Start - One Command!

```bash
./run_web_ui.sh
```

**That's all you need!** The script will:
- ✅ Check all dependencies
- ✅ Start the web server  
- ✅ Print a clickable link in the terminal
- ✅ Automatically open your browser

Then:
1. Select a network interface
2. Click **Start** to capture packets
3. Watch real-time network traffic

## 📊 Dashboard Features

- **Live Statistics**: Total packets, bytes, packet rate, alerts
- **Protocol Chart**: Real-time pie chart of network protocols
- **Packet Rate Graph**: Line chart showing packets per second
- **Live Packet Table**: Last 100 captured packets with details
- **Alert Highlighting**: Suspicious packets highlighted instantly
- **Interface Selection**: Dropdown to choose network interface
- **Real-time Updates**: WebSocket-based instant data streaming

## 🔧 Installation (First Time Only)

```bash
pip install -r requirements.txt
```

## ⚙️ System Requirements

- Python 3.8+
- macOS, Linux, or Windows
- Network packet capture may require elevated privileges (`sudo`)

## 🛠️ Advanced Options

```bash
# Custom port
python -m network_analyzer --web --port 8080

# Custom host
python -m network_analyzer --web --host 0.0.0.0

# List available interfaces
python -m network_analyzer --list-interfaces

# Analyze existing PCAP file
python -m network_analyzer -p capture.pcap
```

## 📁 Project Structure

```
network_analyzer/
├── modules/              # Core analysis modules
├── web/                  # Web dashboard
│   ├── app.py           # Flask web server
│   ├── templates/       # HTML dashboard
│   └── static/          # CSS & JavaScript
└── __main__.py          # Entry point
```

## ❓ Troubleshooting

**Port already in use?**
```bash
python -m network_analyzer --web --port 8080
```

**Permission denied?**
```bash
sudo ./run_web_ui.sh
```

**Browser won't connect?**
- Make sure terminal shows "Starting web server..."
- Visit: `http://localhost:5000`
- Check firewall settings

## 📖 How It Works

1. **Packet Capture**: Intercepts live network traffic
2. **Analysis**: Extracts protocol information and packet details  
3. **Classification**: Identifies TCP, UDP, ICMP, HTTP, DNS, etc.
4. **Statistics**: Calculates bandwidth and traffic patterns
5. **Alerts**: Detects suspicious activities
6. **Dashboard**: Real-time web visualization via WebSocket

## 🔒 Security

- All analysis is local - no external data transmission
- Packet capture requires elevated privileges
- Data stored only in memory and local logs
- Cannot decrypt encrypted traffic

## ⚡ What's Inside

- **Packet Capture Module**: Real-time network packet capture
- **Packet Analysis Module**: Deep inspection of packet headers and payloads
- **Protocol Classification**: Automatic TCP, UDP, ICMP, HTTP, DNS detection
- **Traffic Statistics**: Bandwidth usage and performance metrics
- **Alert Detection**: Identifies suspicious network activities
- **Web Dashboard**: Flask + Socket.IO for real-time visualization

## 📝 License

MIT License - See LICENSE file

---

**Ready? Run:** `./run_web_ui.sh` 🚀


## Author

Network Security Team
Version 1.0.0
