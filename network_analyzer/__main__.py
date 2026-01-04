"""
Main Application
Orchestrates all modules and provides command-line interface
"""

import sys
import argparse
import time
from datetime import datetime
import logging
from typing import Optional

from network_analyzer.modules.packet_capture import PacketCapture
from network_analyzer.modules.packet_filtering import PacketFilter
from network_analyzer.modules.packet_analysis import PacketAnalyzer
from network_analyzer.modules.protocol_classification import ProtocolClassifier
from network_analyzer.modules.traffic_statistics import TrafficStatistics
from network_analyzer.modules.alert_detection import AlertDetection
from network_analyzer.modules.logging_reporting import LoggingReporting
from network_analyzer.modules.visualization import Dashboard
from network_analyzer.web.app import run_web_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/network_analyzer.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class NetworkAnalyzerApp:
    """Main application class orchestrating all modules"""
    
    def __init__(self):
        """Initialize the application"""
        self.packet_capture = PacketCapture(max_packets=5000)
        self.packet_filter = PacketFilter()
        self.analyzer = PacketAnalyzer()
        self.classifier = ProtocolClassifier()
        self.statistics = TrafficStatistics()
        self.alert_detector = AlertDetection()
        self.logger = LoggingReporting()
        self.dashboard = Dashboard()
        
        logger.info("Network Analyzer initialized")
    
    def on_packet_received(self, packet):
        """Callback when packet is received"""
        try:
            # Analyze packet
            analysis = self.analyzer.analyze_packet(packet)
            
            # Classify protocol
            classification = self.classifier.classify_packet(packet)
            analysis["classification"] = classification
            
            # Update statistics
            self.statistics.process_packet(packet)
            
            # Check for alerts
            alert = self.alert_detector.check_packet(packet)
            if alert:
                self.logger.log_alert(alert)
            
            # Log packet
            self.logger.log_packet(packet, analysis)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def start_capture(self, interface: Optional[str] = None, 
                     packet_count: Optional[int] = None,
                     filter_str: Optional[str] = None):
        """Start packet capture on interface"""
        
        # Get available interfaces if not specified
        if not interface:
            interfaces = self.packet_capture.get_interfaces()
            if not interfaces:
                logger.error("No network interfaces available")
                return
            
            print("\nAvailable network interfaces:")
            for i, iface in enumerate(interfaces):
                print(f"  {i+1}. {iface}")
            
            choice = input("\nSelect interface number (default: 1): ").strip()
            try:
                idx = int(choice) - 1 if choice else 0
                interface = interfaces[idx]
            except (ValueError, IndexError):
                print("Invalid selection")
                return
        
        print(f"\n{'='*60}")
        print(f"Starting packet capture on interface: {interface}")
        if filter_str:
            print(f"Filter: {filter_str}")
        print(f"{'='*60}\n")
        
        # Add packet callback
        self.packet_capture.add_callback(self.on_packet_received)
        
        # Start capture
        try:
            self.packet_capture.start_capture(interface, packet_count, filter_str)
            
            # Display real-time updates
            self._display_realtime_stats()
            
        except KeyboardInterrupt:
            print("\n\nCapture interrupted by user")
            self.stop_capture()
        except PermissionError:
            logger.error("Packet capture requires root/administrator privileges")
            print("Please run with sudo: sudo python -m network_analyzer")
    
    def _display_realtime_stats(self):
        """Display real-time statistics during capture"""
        try:
            while self.packet_capture.is_capturing:
                time.sleep(5)  # Update every 5 seconds
                
                stats = self.statistics.get_summary()
                capture_stats = self.packet_capture.get_stats()
                protocol_dist = self.classifier.get_protocol_distribution()
                alerts = self.alert_detector.get_alerts()
                
                # Update dashboard
                self.dashboard.update_metrics(stats, alerts, protocol_dist)
                
                # Print dashboard
                self.dashboard.print_dashboard()
                
                print(f"\nCapture Status: {capture_stats['total_packets']} packets captured " 
                      f"({capture_stats['packets_per_second']:.2f} pps)")
                print("Press Ctrl+C to stop and generate report\n")
        
        except KeyboardInterrupt:
            pass
    
    def stop_capture(self):
        """Stop packet capture and generate report"""
        self.packet_capture.stop_capture()
        
        # Generate final statistics
        stats = self.statistics.get_summary()
        alerts = self.alert_detector.get_alerts()
        protocol_dist = self.classifier.get_protocol_distribution()
        
        print("\n" + "="*80)
        print("  FINAL REPORT".center(80))
        print("="*80)
        
        print(f"\nCapture Duration: {stats['elapsed_time']:.2f} seconds")
        print(f"Total Packets Captured: {stats['total_packets']:,}")
        print(f"Total Data: {stats['total_bytes'] / 1_000_000:.2f} MB")
        print(f"Average Bandwidth: {stats['bandwidth_mbps']:.2f} Mbps")
        print(f"Packets per Second: {stats['pps']:.2f}")
        
        print("\nProtocol Distribution:")
        for proto, percentage in self.classifier.get_protocol_percentage().items():
            print(f"  {proto:15} {percentage:6.2f}%")
        
        print(f"\nTotal Alerts: {len(alerts)}")
        if alerts:
            alert_summary = self.alert_detector.get_alert_summary()
            print("Alert Summary:")
            for alert_type, count in alert_summary.items():
                print(f"  {alert_type:20} {count:>5}")
        
        print("\n" + "-"*80)
        print("Generating reports...")
        
        # Export logs
        json_file = self.logger.export_packets_to_json()
        csv_file = self.logger.export_packets_to_csv()
        html_file = self.logger.export_html_report(stats, alerts)
        alert_file = self.logger.export_alerts_to_json()
        
        print(f"  JSON packets: {json_file}")
        print(f"  CSV packets:  {csv_file}")
        print(f"  HTML report:  {html_file}")
        print(f"  JSON alerts:  {alert_file}")
        
        print("\n" + "="*80)
        print("Report generation complete!")
        print("="*80 + "\n")
    
    def analyze_pcap_file(self, filepath: str):
        """Analyze a saved PCAP file"""
        from scapy.all import rdpcap
        
        try:
            print(f"\nAnalyzing PCAP file: {filepath}\n")
            packets = rdpcap(filepath)
            
            for i, packet in enumerate(packets):
                if not self.packet_capture.is_capturing:
                    break
                self.on_packet_received(packet)
                
                if (i + 1) % 100 == 0:
                    print(f"Processed {i + 1} packets...")
            
            print(f"\nTotal packets processed: {len(packets)}")
            
            # Generate report
            stats = self.statistics.get_summary()
            alerts = self.alert_detector.get_alerts()
            
            self.logger.export_html_report(stats, alerts)
            
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System - Network Protocol Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start interactive capture (requires sudo)
  sudo python -m network_analyzer
  
  # Capture on specific interface
  sudo python -m network_analyzer -i en0
  
  # Capture only TCP traffic
  sudo python -m network_analyzer -i en0 -f "tcp"
  
  # Analyze PCAP file
  python -m network_analyzer -p /path/to/file.pcap
  
  # List available interfaces
  python -m network_analyzer --list-interfaces
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-f', '--filter', help='BPF filter (e.g., "tcp port 80")')
    parser.add_argument('-p', '--pcap', help='Analyze PCAP file')
    parser.add_argument('--list-interfaces', action='store_true', 
                       help='List available network interfaces')
    parser.add_argument('--web', action='store_true', help='Launch web-based UI (default)')
    parser.add_argument('--host', default='127.0.0.1', help='Web server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Web server port (default: 5000)')
    
    args = parser.parse_args()
    
    app = NetworkAnalyzerApp()
    
    if args.list_interfaces:
        interfaces = app.packet_capture.get_interfaces()
        print("\nAvailable network interfaces:")
        for iface in interfaces:
            print(f"  - {iface}")
        return
    
    # Default to web UI
    if args.web or (not args.pcap and not args.list_interfaces):
        try:
            run_web_server(host=args.host, port=args.port, debug=False)
        except KeyboardInterrupt:
            print("\n\nShutting down web server...")
        return
    
    if args.pcap:
        app.analyze_pcap_file(args.pcap)
        return
    
    # Start live capture
    app.start_capture(args.interface, args.count, args.filter)


if __name__ == '__main__':
    main()
