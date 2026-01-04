# Network Analyzer

A real-time network traffic monitor and intrusion detection system with a modern web dashboard.

## Features
- **Live Monitoring**: Visualize network traffic in real-time with interactive charts
- **Intrusion Detection**: Automatically detects port scans, suspicious flags, and traffic spikes
- **Protocol Analysis**: Detailed breakdown of HTTP, HTTPS, DNS, TCP, UDP traffic
- **Alert System**: Real-time alerts for suspicious network activity
- **Dashboard Reset**: Clear all captured data with one click
- **Export**: Download logs as JSON or CSV
- **CLI Manager**: Interactive command-line interface with network animation

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/gau-rhv/network-analyzer-web.git
   cd network-analyzer-web
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   sudo ./run_web_ui.sh
   ```
   (Sudo is required for raw packet capture)

4. **Open Dashboard**
   Go to `http://127.0.0.1:5002` in your browser.

## Tech Stack
- **Backend**: Python, Flask, Flask-SocketIO, Scapy
- **Frontend**: HTML5, Bootstrap 5, Chart.js, Socket.IO
- **Analysis**: Real-time packet inspection and protocol classification
