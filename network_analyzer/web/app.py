"""
Flask Web Application for Network Analyzer
Real-time network monitoring dashboard
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import json
from datetime import datetime
from collections import deque
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.packet_capture import PacketCapture
from modules.packet_filtering import PacketFilter
from modules.packet_analysis import PacketAnalyzer
from modules.protocol_classification import ProtocolClassifier
from modules.traffic_statistics import TrafficStatistics
from modules.alert_detection import AlertDetection
from modules.visualization import Dashboard
from modules.logging_reporting import LoggingReporting

app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/static')
app.config['SECRET_KEY'] = 'network-analyzer-secret-2025'
app.config['JSON_SORT_KEYS'] = False

socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=10,
    ping_interval=5
)

# Global state
capture_thread = None
is_capturing = False
packet_buffer = deque(maxlen=100)
stats_buffer = deque(maxlen=50)

# Initialize modules
packet_capture = None
packet_analyzer = PacketAnalyzer()
protocol_classifier = ProtocolClassifier()
traffic_stats = TrafficStatistics()
alert_detection = AlertDetection()
logging_reporter = LoggingReporting()


def capture_packets(interface, packet_count=0):
    """Capture packets and emit via WebSocket"""
    global is_capturing, packet_capture
    
    try:
        print(f"[DEBUG] Starting packet capture on interface: {interface}")
        packet_capture = PacketCapture()
        is_capturing = True
        
        socketio.server.emit('status', {
            'status': 'capturing',
            'interface': interface,
            'timestamp': datetime.now().isoformat()
        })
        
        captured_count = 0
        
        def packet_callback(packet):
            nonlocal captured_count
            if not is_capturing:
                return False
            
            try:
                # Analyze packet
                analysis = packet_analyzer.analyze(packet)
                if analysis:
                    # Classify protocol
                    protocol = protocol_classifier.classify(packet)
                    
                    src_ip = analysis.get('source_ip', 'N/A')
                    dst_ip = analysis.get('dest_ip', 'N/A')
                    src_port = analysis.get('source_port', 'N/A')
                    dst_port = analysis.get('dest_port', 'N/A')
                    
                    print(f"[PKT] {protocol} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Size: {analysis.get('packet_size', 0)}B")
                    
                    # Log to file reporter
                    logging_reporter.log_packet(packet, analysis)
                    
                    # Detect alerts
                    alert = alert_detection.check_packet(packet)
                    alerts = [alert['type']] if alert else []
                    
                    packet_data = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': src_ip,
                        'dest_ip': dst_ip,
                        'source_port': src_port,
                        'dest_port': dst_port,
                        'protocol': protocol,
                        'packet_size': analysis.get('packet_size', 0),
                        'flags': analysis.get('flags', []),
                        'alerts': alerts,
                    }
                    
                    packet_buffer.append(packet_data)
                    traffic_stats.process_packet(packet)
                    
                    # Emit packet update
                    socketio.server.emit('packet_update', packet_data)
                    
                    # Emit statistics update every 10 packets
                    if captured_count % 10 == 0:
                        stats = {
                            'total_packets': traffic_stats.total_packets,
                            'total_bytes': traffic_stats.total_bytes,
                            'protocol_distribution': traffic_stats.get_protocol_statistics(),
                            'timestamp': datetime.now().isoformat()
                        }
                        stats_buffer.append(stats)
                        socketio.server.emit('stats_update', stats)
                
                captured_count += 1
                
                # Stop if packet_count is specified
                if packet_count > 0 and captured_count >= packet_count:
                    return False
                    
            except Exception as e:
                print(f"Error processing packet: {e}")
            
            return True
        
        # Add callback to packet capture
        packet_capture.add_callback(packet_callback)
        
        print(f"[DEBUG] Calling start_capture with interface={interface}, count={packet_count}")
        packet_capture.start_capture(interface, packet_count, None)
        print(f"[DEBUG] start_capture returned - capture thread is now running in background")
        
    except Exception as e:
        print(f"[DEBUG] Exception in capture_packets: {e}")
        import traceback
        traceback.print_exc()
        is_capturing = False
        socketio.server.emit('error', {'message': str(e)})


@app.route('/', methods=['GET'])
def index():
    """Serve main dashboard"""
    try:
        return render_template('index.html')
    except Exception as e:
        return f"Error loading dashboard: {str(e)}", 500


@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    try:
        import psutil
        interfaces = {}
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == 'AF_INET':
                    interfaces[iface] = addr.address
                    break
        return jsonify(interfaces)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/packets')
def get_packets():
    """Get captured packets"""
    return jsonify(list(packet_buffer))


@app.route('/api/stats')
def get_stats():
    """Get traffic statistics"""
    if not traffic_stats.total_packets:
        return jsonify({
            'total_packets': 0,
            'total_bytes': 0,
            'protocol_distribution': {},
            'timestamp': datetime.now().isoformat()
        })
    
    return jsonify({
        'total_packets': traffic_stats.total_packets,
        'total_bytes': traffic_stats.total_bytes,
        'protocol_distribution': traffic_stats.get_protocol_distribution(),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/start-capture', methods=['POST'])
def start_capture():
    """Start packet capture"""
    global capture_thread, is_capturing
    
    if is_capturing:
        return jsonify({'status': 'already_running'}), 400
    
    interface = request.json.get('interface', 'en0')
    packet_count = request.json.get('count', 0)
    
    capture_thread = threading.Thread(
        target=capture_packets,
        args=(interface, packet_count),
        daemon=True
    )
    capture_thread.start()
    
    return jsonify({'status': 'started', 'interface': interface})


@app.route('/api/stop-capture', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global is_capturing
    is_capturing = False
    return jsonify({'status': 'stopped'})

@app.route('/api/reset', methods=['POST'])
def reset_dashboard():
    global packet_buffer, stats_buffer, traffic_stats
    
    packet_buffer.clear()
    stats_buffer.clear()
    traffic_stats = TrafficStatistics()
    if packet_capture:
        packet_capture.clear_packets()
        
    socketio.server.emit('reset', {'timestamp': datetime.now().isoformat()})
    return jsonify({'status': 'reset'})

@app.route('/api/system/save_logs', methods=['POST'])
def save_logs_on_exit():
    try:
        filepath = logging_reporter.export_packets_to_json()
        return jsonify({'status': 'saved', 'path': filepath})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', {
        'status': 'connected',
        'timestamp': datetime.now().isoformat()
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    global is_capturing
    is_capturing = False


@app.errorhandler(403)
def forbidden(e):
    """Handle forbidden errors"""
    return jsonify({'error': 'Forbidden'}), 403


@app.errorhandler(404)
def not_found(e):
    """Handle not found errors"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    """Handle server errors"""
    return jsonify({'error': str(e)}), 500


def run_web_server(host='127.0.0.1', port=5000, debug=False):
    """Run the Flask web server"""
    print(f"\n{'='*60}")
    print(f"Network Analyzer - Web UI")
    print(f"{'='*60}")
    print(f"Starting web server on http://{host}:{port}")
    print(f"{'='*60}\n")
    
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    run_web_server(debug=True)
