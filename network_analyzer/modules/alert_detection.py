from scapy.all import IP, TCP, UDP, ICMP
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class AlertDetection:
    
    
    def __init__(self):
        
        self.alerts = []
        self.ip_packet_count = defaultdict(int)
        self.port_scan_candidates = {}
        self.traffic_threshold = 1000
        self.last_cleanup = datetime.now()
    
    def check_packet(self, packet) -> Optional[Dict]:
        
        alert = None
        
        if IP not in packet:
            return None
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            if tcp_layer.flags & 0x02:
                alert = self._check_port_scan(src_ip, tcp_layer.dport)
        
        alert = alert or self._check_traffic_spike(src_ip)
        
        if ICMP in packet:
            alert = alert or self._check_icmp_anomaly(packet[ICMP])
        
        if TCP in packet:
            alert = alert or self._check_invalid_tcp_flags(packet[TCP])
        
        if alert:
            self.alerts.append(alert)
        
        return alert
    
    def _check_port_scan(self, src_ip: str, dst_port: int) -> Optional[Dict]:
        
        port_key = f"{src_ip}:{dst_port}"
        
        if src_ip not in self.port_scan_candidates:
            self.port_scan_candidates[src_ip] = defaultdict(int)
        
        self.port_scan_candidates[src_ip][dst_port] += 1
        
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
        
        icmp_type = icmp_layer.type
        
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
        
        flags = tcp_layer.flags
        
        if (flags & 0x01) and (flags & 0x04) and (flags & 0x08):
            return {
                "type": "INVALID_TCP_FLAGS",
                "severity": "MEDIUM",
                "flags": str(flags),
                "timestamp": datetime.now(),
                "description": "Invalid TCP flag combination detected (FIN+RST+PSH)"
            }
        
        if flags == 0:
            return {
                "type": "NULL_TCP_FLAGS",
                "severity": "MEDIUM",
                "timestamp": datetime.now(),
                "description": "TCP packet with no flags detected"
            }
        
        return None
    
    def get_alerts(self, limit: Optional[int] = None) -> List[Dict]:
        
        if limit:
            return self.alerts[-limit:]
        return self.alerts
    
    def get_recent_alerts(self, minutes: int = 5) -> List[Dict]:
        
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [a for a in self.alerts if a["timestamp"] > cutoff_time]
    
    def get_alert_summary(self) -> Dict[str, int]:
        
        summary = defaultdict(int)
        for alert in self.alerts:
            summary[alert["type"]] += 1
        return dict(summary)
    
    def clear_alerts(self):
        
        self.alerts.clear()
        logger.info("Alerts cleared")
    
    def cleanup_old_data(self):
        
        if datetime.now() - self.last_cleanup > timedelta(minutes=5):
            self.ip_packet_count.clear()
            self.port_scan_candidates.clear()
            self.last_cleanup = datetime.now()
