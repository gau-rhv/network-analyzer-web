from scapy.all import IP, TCP, UDP, ICMP, Raw
from typing import List, Optional, Callable
import logging

logger = logging.getLogger(__name__)

class PacketFilter:
    
    
    def __init__(self):
        
        self.filters = []
    
    def add_protocol_filter(self, protocols: List[str]) -> Callable:
        
        def filter_func(packet):
            if TCP in packet and 'TCP' in protocols:
                return True
            if UDP in packet and 'UDP' in protocols:
                return True
            if ICMP in packet and 'ICMP' in protocols:
                return True
            
            if TCP in packet:
                if 'HTTP' in protocols and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    return True
                if 'FTP' in protocols and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
                    return True
                if 'SSH' in protocols and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
                    return True
                if 'HTTPS' in protocols and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                    return True
            
            if UDP in packet:
                if 'DNS' in protocols and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
                    return True
            
            return False
        
        self.filters.append(filter_func)
        return filter_func
    
    def add_ip_filter(self, src_ip: Optional[str] = None, 
                     dst_ip: Optional[str] = None) -> Callable:
        
        def filter_func(packet):
            if IP not in packet:
                return False
            
            if src_ip and packet[IP].src != src_ip:
                return False
            if dst_ip and packet[IP].dst != dst_ip:
                return False
            
            return True
        
        self.filters.append(filter_func)
        return filter_func
    
    def add_port_filter(self, src_port: Optional[int] = None,
                       dst_port: Optional[int] = None) -> Callable:
        
        def filter_func(packet):
            if TCP in packet:
                if src_port and packet[TCP].sport != src_port:
                    return False
                if dst_port and packet[TCP].dport != dst_port:
                    return False
                return True
            
            if UDP in packet:
                if src_port and packet[UDP].sport != src_port:
                    return False
                if dst_port and packet[UDP].dport != dst_port:
                    return False
                return True
            
            return False
        
        self.filters.append(filter_func)
        return filter_func
    
    def apply_filters(self, packets: List) -> List:
        
        if not self.filters:
            return packets
        
        filtered = packets
        for filter_func in self.filters:
            filtered = [p for p in filtered if filter_func(p)]
        
        return filtered
    
    def reset_filters(self):
        
        self.filters.clear()
        logger.info("Filters reset")
    
    def get_filter_count(self) -> int:
        
        return len(self.filters)
