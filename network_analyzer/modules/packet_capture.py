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
    def __init__(self, max_packets=10000):
        self.max_packets = max_packets
        self.packets = deque(maxlen=max_packets)
        self.is_capturing = False
        self.capture_thread = None
        self.callbacks = []
        self.packet_count = 0
        self.start_time = None
        
    def get_interfaces(self):
        try:
            return scapy.get_if_list()
        except:
            return []
    
    def add_callback(self, callback):
        self.callbacks.append(callback)
    
    def start_capture(self, interface, packet_count=None, filter_str=None):
        if self.is_capturing:
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
    
    def _capture_packets(self, interface, packet_count, filter_str):
        try:
            def packet_callback(packet):
                if not self.is_capturing:
                    return
                
                self.packets.append(packet)
                self.packet_count += 1
                
                for callback in self.callbacks:
                    try:
                        callback(packet)
                    except:
                        pass
                
                if packet_count and self.packet_count >= packet_count:
                    self.stop_capture()
            
            kwargs = {"iface": interface, "prn": packet_callback}
            if filter_str: kwargs["filter"] = filter_str
            if packet_count: kwargs["count"] = packet_count
            
            scapy.sniff(**kwargs)
            
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.stop_capture()
    
    def stop_capture(self):
        self.is_capturing = False
    
    def get_packets(self, limit=None):
        if limit:
            return list(self.packets)[-limit:]
        return list(self.packets)
    
    def get_stats(self):
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        pps = self.packet_count / elapsed if elapsed > 0 else 0
        return {
            "total_packets": self.packet_count,
            "elapsed_time": elapsed,
            "packets_per_second": pps,
            "is_capturing": self.is_capturing
        }
    
    def clear_packets(self):
        self.packets.clear()
