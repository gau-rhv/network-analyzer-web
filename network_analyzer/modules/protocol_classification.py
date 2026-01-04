from scapy.all import IP, TCP, UDP, ICMP
from typing import Dict, List, Optional
from collections import Counter
import logging

logger = logging.getLogger(__name__)

class ProtocolClassifier:
    
    
    PROTOCOL_NAMES = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    
    PORT_SERVICES = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-PROXY",
        8443: "HTTPS-ALT"
    }
    
    def __init__(self):
        
        self.protocol_stats = Counter()
        self.port_stats = Counter()
    
    def classify(self, packet) -> str:
        
        classification = self.classify_packet(packet)
        
        app_protocol = classification.get("application", "Unknown")
        if app_protocol and app_protocol != "Unknown":
            return app_protocol
        
        return classification.get("transport", "Unknown")
    
    def classify_packet(self, packet) -> Dict[str, str]:
        
        classification = {
            "link": "Unknown",
            "network": "Unknown",
            "transport": "Unknown",
            "application": "Unknown"
        }
        
        classification["link"] = "Ethernet"
        
        if IP in packet:
            classification["network"] = "IPv4"
        
        if TCP in packet:
            classification["transport"] = "TCP"
            tcp_layer = packet[TCP]
            self.protocol_stats["TCP"] += 1
            self.port_stats[tcp_layer.dport] += 1
            
            classification["application"] = self._classify_tcp_application(
                tcp_layer.sport, tcp_layer.dport
            )
        
        elif UDP in packet:
            classification["transport"] = "UDP"
            udp_layer = packet[UDP]
            self.protocol_stats["UDP"] += 1
            self.port_stats[udp_layer.dport] += 1
            
            classification["application"] = self._classify_udp_application(
                udp_layer.sport, udp_layer.dport
            )
        
        elif ICMP in packet:
            classification["transport"] = "ICMP"
            self.protocol_stats["ICMP"] += 1
            classification["application"] = "ICMP"
        
        return classification
    
    @staticmethod
    def _classify_tcp_application(sport: int, dport: int) -> str:
        
        for port in [sport, dport]:
            if port in ProtocolClassifier.PORT_SERVICES:
                return ProtocolClassifier.PORT_SERVICES[port]
        
        if dport in [80, 8080, 8000, 8888]:
            return "HTTP"
        elif dport in [443, 8443]:
            return "HTTPS"
        elif dport in [21, 22]:
            return "SSH/FTP"
        elif dport in [23]:
            return "TELNET"
        elif dport in [25, 587, 465]:
            return "SMTP"
        elif dport in [53]:
            return "DNS"
        
        return "Unknown-TCP"
    
    @staticmethod
    def _classify_udp_application(sport: int, dport: int) -> str:
        
        for port in [sport, dport]:
            if port in ProtocolClassifier.PORT_SERVICES:
                return ProtocolClassifier.PORT_SERVICES[port]
        
        if dport in [53]:
            return "DNS"
        elif dport in [67, 68]:
            return "DHCP"
        elif dport in [123]:
            return "NTP"
        elif dport in [161]:
            return "SNMP"
        
        return "Unknown-UDP"
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        
        return dict(self.protocol_stats)
    
    def get_top_ports(self, limit: int = 10) -> List[tuple]:
        
        return self.port_stats.most_common(limit)
    
    def get_protocol_percentage(self) -> Dict[str, float]:
        
        total = sum(self.protocol_stats.values())
        if total == 0:
            return {}
        
        return {
            protocol: (count / total) * 100
            for protocol, count in self.protocol_stats.items()
        }
    
    def reset_stats(self):
        
        self.protocol_stats.clear()
        self.port_stats.clear()
