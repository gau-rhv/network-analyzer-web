"""
Packet Capture Module
Captures live network packets from selected network interfaces
"""

import scapy.all as scapy
import threading
from typing import Callable, List, Optional
from collections import deque
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PacketCapture:
    """Captures live network packets from network interfaces"""
    
    def __init__(self, max_packets: int = 10000):
        """
        Initialize packet capture
        
        Args:
            max_packets: Maximum packets to store in memory
        """
        self.max_packets = max_packets
        self.packets = deque(maxlen=max_packets)
        self.is_capturing = False
        self.capture_thread = None
        self.callbacks = []
        self.packet_count = 0
        self.start_time = None
        
    def get_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        try:
            interfaces = scapy.get_if_list()
            return interfaces
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return []
    
    def add_callback(self, callback: Callable):
        """Add callback function to process packets in real-time"""
        self.callbacks.append(callback)
    
    def start_capture(self, interface: str, packet_count: Optional[int] = None, 
                     filter_str: Optional[str] = None):
        """
        Start capturing packets on specified interface
        
        Args:
            interface: Network interface name
            packet_count: Maximum packets to capture (None = infinite)
            filter_str: BPF filter string (e.g., "tcp port 80")
        """
        if self.is_capturing:
            logger.warning("Already capturing packets")
            return
        
        self.is_capturing = True
        self.packet_count = 0
        self.start_time = datetime.now()
        
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, packet_count, filter_str),
            daemon=True
        )
        self.capture_thread.start()
        logger.info(f"Started packet capture on interface: {interface}")
    
    def _capture_packets(self, interface: str, packet_count: Optional[int], 
                        filter_str: Optional[str]):
        """Internal method to capture packets"""
        try:
            def packet_callback(packet):
                if not self.is_capturing:
                    return
                
                self.packets.append(packet)
                self.packet_count += 1
                
                # Call registered callbacks
                for callback in self.callbacks:
                    try:
                        callback(packet)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")
                
                # Stop if packet count reached
                if packet_count and self.packet_count >= packet_count:
                    self.stop_capture()
            
            kwargs = {"iface": interface, "prn": packet_callback}
            
            if filter_str:
                kwargs["filter"] = filter_str
            
            if packet_count:
                kwargs["count"] = packet_count
            
            scapy.sniff(**kwargs)
            
        except PermissionError:
            logger.error("Packet capture requires root/administrator privileges")
            self.is_capturing = False
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.is_capturing = False
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        logger.info(f"Stopped packet capture. Total packets: {self.packet_count}")
    
    def get_packets(self, limit: Optional[int] = None) -> List:
        """Get captured packets"""
        if limit:
            return list(self.packets)[-limit:]
        return list(self.packets)
    
    def get_stats(self) -> dict:
        """Get capture statistics"""
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        pps = self.packet_count / elapsed if elapsed > 0 else 0
        
        return {
            "total_packets": self.packet_count,
            "elapsed_time": elapsed,
            "packets_per_second": pps,
            "buffered_packets": len(self.packets),
            "is_capturing": self.is_capturing
        }
    
    def clear_packets(self):
        """Clear captured packets from memory"""
        self.packets.clear()
        logger.info("Cleared packet buffer")
