# Network Analyzer

A real-time network traffic monitor and intrusion detection system.

## Features
*   **Live Monitoring**: Visualize network traffic in real-time.
*   **Intrusion Detection**: Automatically detects port scans, suspicious flags, and traffic spikes.
*   **Protocol Analysis**: Detailed breakdown of HTTP, DNS, TCP, UDP traffic.
*   **Export**: Download logs as JSON or CSV.

## Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/gau-rhv/network-analyzer-web.git
    cd network-analyzer-web
    ```

2.  **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application**
    ```bash
    sudo ./run_web_ui.sh
    ```
    (Sudo is required for raw packet capture)

4.  **Open Dashboard**
    The CLI will launch the server on `http://127.0.0.1:5002`.

## Tech Stack
*   **Backend**: Python, Flask, Scapy
*   **Frontend**: HTML5, Bootstrap 5, Chart.js, WebSocket
