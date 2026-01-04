from scapy.all import IP, TCP, UDP, ICMP, Raw
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class PacketAnalyzer:
    @staticmethod
    def analyze_packet(packet) -> Dict[str, Any]:
        analysis = {
            "timestamp": packet.time if hasattr(packet, 'time') else None,
            "size": len(packet),
            "layers": packet.layers(),
        }
        
        if IP in packet:
            ip_layer = packet[IP]
            analysis["ip"] = {
                "src": ip_layer.src,
                "dst": ip_layer.dst,
                "version": ip_layer.version,
                "ttl": ip_layer.ttl,
                "protocol": ip_layer.proto,
                "flags": ip_layer.flags,
                "ihl": ip_layer.ihl,
                "length": ip_layer.len
            }
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            analysis["tcp"] = {
                "src_port": tcp_layer.sport,
                "dst_port": tcp_layer.dport,
                "sequence": tcp_layer.seq,
                "acknowledgment": tcp_layer.ack,
                "flags": str(tcp_layer.flags),
                "window": tcp_layer.window,
                "payload_size": len(tcp_layer.payload)
            }
        
        if UDP in packet:
            udp_layer = packet[UDP]
            analysis["udp"] = {
                "src_port": udp_layer.sport,
                "dst_port": udp_layer.dport,
                "length": udp_layer.len,
                "payload_size": len(udp_layer.payload)
            }
        
        if ICMP in packet:
            icmp_layer = packet[ICMP]
            analysis["icmp"] = {
                "type": icmp_layer.type,
                "code": icmp_layer.code,
                "id": getattr(icmp_layer, 'id', None),
                "sequence": getattr(icmp_layer, 'seq', None)
            }
        
        if Raw in packet:
            raw_payload = packet[Raw].load
            analysis["payload"] = {
                "size": len(raw_payload),
                "is_ascii": PacketAnalyzer._is_ascii(raw_payload),
                "hex_preview": raw_payload[:64].hex() if len(raw_payload) > 0 else ""
            }
        
        return analysis
    
    @staticmethod
    def _is_ascii(data: bytes) -> bool:
        try:
            ascii_count = sum(1 for byte in data if 32 <= byte < 127)
            return ascii_count / len(data) > 0.8 if data else False
        except:
            return False
    
    @staticmethod
    def get_protocol_info(packet) -> Dict[str, str]:
        protocols = {}
        
        if IP in packet:
            protocols["network"] = "IPv4"
        
        if TCP in packet:
            protocols["transport"] = "TCP"
        elif UDP in packet:
            protocols["transport"] = "UDP"
        elif ICMP in packet:
            protocols["transport"] = "ICMP"
        
        return protocols
    
    @staticmethod
    def analyze(packet) -> Dict[str, Any]:
        result = {
            'source_ip': 'N/A',
            'dest_ip': 'N/A',
            'source_port': 'N/A',
            'dest_port': 'N/A',
            'packet_size': len(packet),
            'flags': []
        }
        
        if IP in packet:
            result['source_ip'] = packet[IP].src
            result['dest_ip'] = packet[IP].dst
        
        if TCP in packet:
            result['source_port'] = packet[TCP].sport
            result['dest_port'] = packet[TCP].dport
            flags = str(packet[TCP].flags)
            if flags:
                result['flags'] = [flags]
        
        elif UDP in packet:
            result['source_port'] = packet[UDP].sport
            result['dest_port'] = packet[UDP].dport
        
        elif ICMP in packet:
            result['source_port'] = 'N/A'
            result['dest_port'] = 'N/A'
        
        return result
    
    @staticmethod
    def extract_summary(packet) -> str:
        layers = []
        
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            layers.append(f"IP({src} -> {dst})")
        
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = str(packet[TCP].flags)
            layers.append(f"TCP({sport} -> {dport}) [{flags}]")
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            layers.append(f"UDP({sport} -> {dport})")
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            layers.append(f"ICMP(type={icmp_type})")
        
        return " / ".join(layers)
