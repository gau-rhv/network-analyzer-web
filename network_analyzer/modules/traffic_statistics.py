from scapy.all import IP, TCP, UDP
from typing import Dict, Optional
from collections import defaultdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class TrafficStatistics:
    
    
    def __init__(self):
        
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = datetime.now()
        self.ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.protocol_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.flow_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
    
    def process_packet(self, packet):
        
        packet_size = len(packet)
        self.total_packets += 1
        self.total_bytes += packet_size
        
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            self.ip_stats[src_ip]["packets"] += 1
            self.ip_stats[src_ip]["bytes"] += packet_size
            
            self.ip_stats[dst_ip]["packets"] += 1
            self.ip_stats[dst_ip]["bytes"] += packet_size
            
            flow_key = f"{src_ip} -> {dst_ip}"
            self.flow_stats[flow_key]["packets"] += 1
            self.flow_stats[flow_key]["bytes"] += packet_size
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"
        
        self.protocol_stats[protocol]["packets"] += 1
        self.protocol_stats[protocol]["bytes"] += packet_size
    
    def get_bandwidth_stats(self) -> Dict[str, float]:
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        if elapsed == 0:
            elapsed = 1
        
        bandwidth_bps = (self.total_bytes * 8) / elapsed
        
        return {
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "elapsed_seconds": elapsed,
            "bandwidth_bps": bandwidth_bps,
            "bandwidth_mbps": bandwidth_bps / 1_000_000,
            "avg_packet_size": self.total_bytes / self.total_packets if self.total_packets > 0 else 0,
            "packets_per_second": self.total_packets / elapsed
        }
    
    def get_ip_statistics(self, limit: Optional[int] = None) -> Dict[str, dict]:
        
        stats = dict(self.ip_stats)
        
        if limit:
            sorted_stats = sorted(
                stats.items(),
                key=lambda x: x[1]["bytes"],
                reverse=True
            )
            stats = dict(sorted_stats[:limit])
        
        return stats
    
    def get_protocol_statistics(self) -> Dict[str, dict]:
        
        return dict(self.protocol_stats)
    
    def get_flow_statistics(self, limit: Optional[int] = None) -> Dict[str, dict]:
        
        stats = dict(self.flow_stats)
        
        if limit:
            sorted_stats = sorted(
                stats.items(),
                key=lambda x: x[1]["bytes"],
                reverse=True
            )
            stats = dict(sorted_stats[:limit])
        
        return stats
    
    def get_top_communicators(self, limit: int = 10) -> list:
        
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )
        return sorted_ips[:limit]
    
    def get_summary(self) -> Dict:
        
        bandwidth = self.get_bandwidth_stats()
        protocols = self.get_protocol_statistics()
        
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "elapsed_time": bandwidth["elapsed_seconds"],
            "bandwidth_mbps": bandwidth["bandwidth_mbps"],
            "avg_packet_size": bandwidth["avg_packet_size"],
            "pps": bandwidth["packets_per_second"],
            "unique_src_ips": len(set(
                flow.split(" -> ")[0] for flow in self.flow_stats.keys()
            )),
            "unique_dst_ips": len(set(
                flow.split(" -> ")[1] for flow in self.flow_stats.keys()
            )),
            "protocol_distribution": {
                proto: {
                    "packets": stats["packets"],
                    "bytes": stats["bytes"],
                    "percentage": (stats["packets"] / self.total_packets * 100) 
                                 if self.total_packets > 0 else 0
                }
                for proto, stats in protocols.items()
            }
        }
    
    def reset_stats(self):
        
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = datetime.now()
        self.ip_stats.clear()
        self.protocol_stats.clear()
        self.flow_stats.clear()
        logger.info("Statistics reset")
