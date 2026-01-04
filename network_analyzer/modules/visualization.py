"""
Visualization Module
Provides real-time dashboard and graphical displays of network traffic
"""

from typing import Dict, List, Optional
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)


class Dashboard:
    """Real-time network traffic dashboard"""
    
    def __init__(self):
        """Initialize dashboard"""
        self.metrics = {
            "real_time": {},
            "historical": []
        }
    
    def update_metrics(self, stats: Dict, alerts: List[Dict], 
                      classifier_stats: Dict):
        """Update dashboard with latest metrics"""
        self.metrics["real_time"] = {
            "timestamp": datetime.now().isoformat(),
            "statistics": stats,
            "active_alerts": len(alerts),
            "protocol_distribution": classifier_stats
        }
        
        self.metrics["historical"].append(self.metrics["real_time"])
        
        # Keep only last 100 historical entries
        if len(self.metrics["historical"]) > 100:
            self.metrics["historical"] = self.metrics["historical"][-100:]
    
    def get_dashboard_data(self) -> Dict:
        """Get current dashboard data"""
        return self.metrics
    
    def print_dashboard(self):
        """Print ASCII dashboard to console"""
        if not self.metrics["real_time"]:
            print("No data available yet")
            return
        
        stats = self.metrics["real_time"].get("statistics", {})
        protocols = self.metrics["real_time"].get("protocol_distribution", {})
        
        print("\n" + "="*80)
        print("  NETWORK ANALYZER - REAL-TIME DASHBOARD".center(80))
        print("="*80)
        print(f"\nTime: {self.metrics['real_time']['timestamp']}")
        
        print("\n" + "-"*80)
        print("TRAFFIC SUMMARY")
        print("-"*80)
        print(f"  Total Packets:        {stats.get('total_packets', 0):>20,}")
        print(f"  Total Bytes:          {stats.get('total_bytes', 0):>20,}")
        print(f"  Bandwidth (Mbps):     {stats.get('bandwidth_mbps', 0):>20.2f}")
        print(f"  Packets/Second:       {stats.get('pps', 0):>20.2f}")
        print(f"  Avg Packet Size:      {stats.get('avg_packet_size', 0):>20.2f} bytes")
        print(f"  Unique Source IPs:    {stats.get('unique_src_ips', 0):>20,}")
        print(f"  Unique Dest IPs:      {stats.get('unique_dst_ips', 0):>20,}")
        
        print("\n" + "-"*80)
        print("PROTOCOL DISTRIBUTION")
        print("-"*80)
        proto_dist = stats.get('protocol_distribution', {})
        for proto, data in proto_dist.items():
            percentage = data.get('percentage', 0)
            packets = data.get('packets', 0)
            bar_length = int(percentage / 2)
            bar = "█" * bar_length + "░" * (50 - bar_length)
            print(f"  {proto:8} [{bar}] {percentage:5.1f}% ({packets:>8,} packets)")
        
        print("\n" + "-"*80)
        print(f"ACTIVE ALERTS: {self.metrics['real_time']['active_alerts']}")
        print("-"*80)
        
        print("\n" + "="*80)
    
    def generate_json_dashboard(self, filename: Optional[str] = None) -> str:
        """Generate JSON dashboard file"""
        if not filename:
            filename = f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.metrics, f, indent=2, default=str)
        
        return filename


class VisualizationHelper:
    """Helper class for generating visualization data"""
    
    @staticmethod
    def create_pie_chart_data(distribution: Dict) -> Dict:
        """Create pie chart data for protocol distribution"""
        labels = list(distribution.keys())
        values = [distribution[p] for p in labels]
        
        return {
            "type": "pie",
            "labels": labels,
            "values": values
        }
    
    @staticmethod
    def create_bar_chart_data(ip_stats: Dict, limit: int = 10) -> Dict:
        """Create bar chart data for top IPs"""
        sorted_ips = sorted(
            ip_stats.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )[:limit]
        
        return {
            "type": "bar",
            "labels": [ip for ip, _ in sorted_ips],
            "values": [stats["bytes"] / 1_000_000 for _, stats in sorted_ips]  # Convert to MB
        }
    
    @staticmethod
    def create_timeline_data(historical: List[Dict]) -> Dict:
        """Create timeline data for bandwidth over time"""
        timestamps = []
        bandwidth_values = []
        
        for entry in historical[-50:]:  # Last 50 entries
            timestamps.append(entry.get("timestamp", ""))
            bandwidth = entry.get("statistics", {}).get("bandwidth_mbps", 0)
            bandwidth_values.append(bandwidth)
        
        return {
            "type": "line",
            "timestamps": timestamps,
            "values": bandwidth_values
        }
