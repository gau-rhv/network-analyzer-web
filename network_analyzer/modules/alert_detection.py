"""
Alert & Detection Module
Detects anomalous network traffic and suspicious patterns
"""

from scapy.all import IP, TCP, UDP, ICMP
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class AlertDetection:
    """Detects suspicious network activity and anomalies"""
    
    def __init__(self):
        """Initialize alert detection"""
        self.alerts = []
        self.ip_packet_count = defaultdict(int)
        self.port_scan_candidates = {}
        self.traffic_threshold = 1000  # packets per minute
        self.last_cleanup = datetime.now()
    
    def check_packet(self, packet) -> Optional[Dict]:
        """
        Check packet for anomalies
        
        Returns:
            Alert dictionary if anomaly detected, None otherwise
        """
        alert = None
        
        if IP not in packet:
            return None
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        
        # Check for port scanning
        if TCP in packet:
            tcp_layer = packet[TCP]
            # SYN flag indicates connection attempt
            if tcp_layer.flags & 0x02:  # SYN flag
                alert = self._check_port_scan(src_ip, tcp_layer.dport)
        
        # Check for abnormal packet rates from single source
        alert = alert or self._check_traffic_spike(src_ip)
        
        # Check for suspicious ICMP activity
        if ICMP in packet:
            alert = alert or self._check_icmp_anomaly(packet[ICMP])
        
        # Check for invalid flag combinations
        if TCP in packet:
            alert = alert or self._check_invalid_tcp_flags(packet[TCP])
        
        if alert:
            self.alerts.append(alert)
        
        return alert
    
    def _check_port_scan(self, src_ip: str, dst_port: int) -> Optional[Dict]:
        """Detect potential port scanning activity"""
        port_key = f"{src_ip}:{dst_port}"
        
        if src_ip not in self.port_scan_candidates:
            self.port_scan_candidates[src_ip] = defaultdict(int)
        
        self.port_scan_candidates[src_ip][dst_port] += 1
        
        # Alert if same IP connects to many ports
        unique_ports = len(self.port_scan_candidates[src_ip])
        if unique_ports > 10:
            return {
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "source_ip": src_ip,
                "unique_ports": unique_ports,
                "timestamp": datetime.now(),
                "description": f"Potential port scan detected from {src_ip} targeting {unique_ports} ports"
            }
        
        return None
    
    def _check_traffic_spike(self, src_ip: str) -> Optional[Dict]:
        """Detect sudden traffic spikes from a single source"""
        self.ip_packet_count[src_ip] += 1
        
        if self.ip_packet_count[src_ip] > self.traffic_threshold:
            return {
                "type": "TRAFFIC_SPIKE",
                "severity": "MEDIUM",
                "source_ip": src_ip,
                "packet_count": self.ip_packet_count[src_ip],
                "timestamp": datetime.now(),
                "description": f"High packet rate detected from {src_ip}"
            }
        
        return None
    
    def _check_icmp_anomaly(self, icmp_layer) -> Optional[Dict]:
        """Detect suspicious ICMP activity"""
        icmp_type = icmp_layer.type
        
        # Type 8 is Echo Request (Ping), type 0 is Echo Reply
        # Unusual types might indicate reconnaissance
        if icmp_type not in [0, 8, 11, 3]:
            return {
                "type": "SUSPICIOUS_ICMP",
                "severity": "LOW",
                "icmp_type": icmp_type,
                "timestamp": datetime.now(),
                "description": f"Unusual ICMP type detected: {icmp_type}"
            }
        
        return None
    
    def _check_invalid_tcp_flags(self, tcp_layer) -> Optional[Dict]:
        """Detect invalid or suspicious TCP flag combinations"""
        flags = tcp_layer.flags
        
        # FIN+RST+PSH combination is suspicious
        if (flags & 0x01) and (flags & 0x04) and (flags & 0x08):
            return {
                "type": "INVALID_TCP_FLAGS",
                "severity": "MEDIUM",
                "flags": str(flags),
                "timestamp": datetime.now(),
                "description": "Invalid TCP flag combination detected (FIN+RST+PSH)"
            }
        
        # No flags set is suspicious
        if flags == 0:
            return {
                "type": "NULL_TCP_FLAGS",
                "severity": "MEDIUM",
                "timestamp": datetime.now(),
                "description": "TCP packet with no flags detected"
            }
        
        return None
    
    def get_alerts(self, limit: Optional[int] = None) -> List[Dict]:
        """Get detected alerts"""
        if limit:
            return self.alerts[-limit:]
        return self.alerts
    
    def get_recent_alerts(self, minutes: int = 5) -> List[Dict]:
        """Get alerts from the last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [a for a in self.alerts if a["timestamp"] > cutoff_time]
    
    def get_alert_summary(self) -> Dict[str, int]:
        """Get summary of alerts by type"""
        summary = defaultdict(int)
        for alert in self.alerts:
            summary[alert["type"]] += 1
        return dict(summary)
    
    def clear_alerts(self):
        """Clear alert history"""
        self.alerts.clear()
        logger.info("Alerts cleared")
    
    def cleanup_old_data(self):
        """Clean up old data structures"""
        # Reset counters if they get too large
        if datetime.now() - self.last_cleanup > timedelta(minutes=5):
            self.ip_packet_count.clear()
            self.port_scan_candidates.clear()
            self.last_cleanup = datetime.now()
