"""
Logging & Reporting Module
Stores captured data and generates analysis reports
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
import logging

logger = logging.getLogger(__name__)


class LoggingReporting:
    """Handles logging and report generation"""
    
    def __init__(self, log_dir: str = "logs", report_dir: str = "reports"):
        """
        Initialize logging and reporting
        
        Args:
            log_dir: Directory for log files
            report_dir: Directory for report files
        """
        self.log_dir = Path(log_dir)
        self.report_dir = Path(report_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.report_dir.mkdir(exist_ok=True)
        
        self.packet_log = []
        self.statistics_log = []
        self.alert_log = []
    
    def log_packet(self, packet, analysis: Dict):
        """Log packet information"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "size": len(packet),
            "analysis": analysis
        }
        self.packet_log.append(entry)
    
    def log_statistic(self, stats: Dict):
        """Log traffic statistics"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "data": stats
        }
        self.statistics_log.append(entry)
    
    def log_alert(self, alert: Dict):
        """Log detected alert"""
        self.alert_log.append(alert)
    
    def export_packets_to_json(self, filename: Optional[str] = None) -> str:
        """
        Export packet logs to JSON file
        
        Returns:
            Path to exported file
        """
        if not filename:
            filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = self.log_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.packet_log, f, indent=2, default=str)
        
        logger.info(f"Packets exported to {filepath}")
        return str(filepath)
    
    def export_packets_to_csv(self, filename: Optional[str] = None) -> str:
        """
        Export packet logs to CSV file
        
        Returns:
            Path to exported file
        """
        if not filename:
            filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = self.log_dir / filename
        
        if not self.packet_log:
            logger.warning("No packet logs to export")
            return str(filepath)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=['timestamp', 'size', 'protocol', 'src_ip', 'dst_ip']
            )
            writer.writeheader()
            
            for entry in self.packet_log:
                try:
                    analysis = entry.get('analysis', {})
                    row = {
                        'timestamp': entry['timestamp'],
                        'size': entry['size'],
                        'protocol': analysis.get('protocol', 'Unknown'),
                        'src_ip': analysis.get('ip', {}).get('src', 'N/A'),
                        'dst_ip': analysis.get('ip', {}).get('dst', 'N/A'),
                    }
                    writer.writerow(row)
                except Exception as e:
                    logger.error(f"Error writing CSV row: {e}")
        
        logger.info(f"Packets exported to {filepath}")
        return str(filepath)
    
    def export_alerts_to_json(self, filename: Optional[str] = None) -> str:
        """
        Export alert logs to JSON file
        
        Returns:
            Path to exported file
        """
        if not filename:
            filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = self.log_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.alert_log, f, indent=2, default=str)
        
        logger.info(f"Alerts exported to {filepath}")
        return str(filepath)
    
    def generate_summary_report(self) -> Dict:
        """Generate summary report of all captured data"""
        return {
            "report_time": datetime.now().isoformat(),
            "total_packets": len(self.packet_log),
            "total_alerts": len(self.alert_log),
            "total_statistics_snapshots": len(self.statistics_log),
        }
    
    def export_html_report(self, stats: Dict, alerts: List[Dict], 
                          filename: Optional[str] = None) -> str:
        """
        Generate HTML report with statistics and alerts
        
        Args:
            stats: Statistics dictionary
            alerts: List of alerts
            filename: Output filename
        
        Returns:
            Path to generated report
        """
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        filepath = self.report_dir / filename
        
        html_content = self._generate_html(stats, alerts)
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Report exported to {filepath}")
        return str(filepath)
    
    @staticmethod
    def _generate_html(stats: Dict, alerts: List[Dict]) -> str:
        """Generate HTML content for report"""
        html = """
        <html>
        <head>
            <title>Network Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                h2 { color: #666; margin-top: 30px; border-bottom: 2px solid #007bff; }
                table { border-collapse: collapse; width: 100%; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #007bff; color: white; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .alert { background-color: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }
                .high { color: #dc3545; font-weight: bold; }
                .medium { color: #fd7e14; font-weight: bold; }
                .low { color: #28a745; font-weight: bold; }
            </style>
        </head>
        <body>
            <h1>Network Traffic Analysis Report</h1>
            <p>Generated: {timestamp}</p>
            
            <h2>Traffic Summary</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Packets</td><td>{total_packets}</td></tr>
                <tr><td>Total Bytes</td><td>{total_bytes}</td></tr>
                <tr><td>Bandwidth (Mbps)</td><td>{bandwidth}</td></tr>
                <tr><td>Avg Packet Size</td><td>{avg_size}</td></tr>
            </table>
            
            <h2>Protocol Distribution</h2>
            <table>
                <tr><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Percentage</th></tr>
                {protocol_rows}
            </table>
            
            <h2>Detected Alerts ({alert_count})</h2>
            {alert_rows}
            
        </body>
        </html>
        """
        
        # Format protocol rows
        protocol_rows = ""
        for proto, data in stats.get('protocol_distribution', {}).items():
            protocol_rows += f"""
            <tr>
                <td>{proto}</td>
                <td>{data['packets']}</td>
                <td>{data['bytes']}</td>
                <td>{data['percentage']:.2f}%</td>
            </tr>
            """
        
        # Format alert rows
        alert_rows = ""
        if alerts:
            for alert in alerts[:50]:  # Show last 50 alerts
                severity_class = alert['severity'].lower()
                alert_rows += f"""
            <div class="alert">
                <span class="{severity_class}">[{alert['severity']}]</span> 
                <strong>{alert['type']}</strong>: {alert.get('description', 'N/A')}
            </div>
            """
        else:
            alert_rows = "<p>No alerts detected.</p>"
        
        return html.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_packets=stats.get('total_packets', 0),
            total_bytes=stats.get('total_bytes', 0),
            bandwidth=f"{stats.get('bandwidth_mbps', 0):.2f}",
            avg_size=f"{stats.get('avg_packet_size', 0):.2f}",
            protocol_rows=protocol_rows,
            alert_count=len(alerts),
            alert_rows=alert_rows
        )
    
    def clear_logs(self):
        """Clear all logs"""
        self.packet_log.clear()
        self.statistics_log.clear()
        self.alert_log.clear()
        logger.info("All logs cleared")
