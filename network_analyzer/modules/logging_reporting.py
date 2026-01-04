import json
import csv
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
import logging

logger = logging.getLogger(__name__)

class LoggingReporting:
    
    
    def __init__(self, log_dir: str = "logs", report_dir: str = "reports"):
        
        self.log_dir = Path(log_dir)
        self.report_dir = Path(report_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.report_dir.mkdir(exist_ok=True)
        
        self.packet_log = []
        self.statistics_log = []
        self.alert_log = []
    
    def log_packet(self, packet, analysis: Dict):
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "size": len(packet),
            "analysis": analysis
        }
        self.packet_log.append(entry)
    
    def log_statistic(self, stats: Dict):
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "data": stats
        }
        self.statistics_log.append(entry)
    
    def log_alert(self, alert: Dict):
        
        self.alert_log.append(alert)
    
    def export_packets_to_json(self, filename: Optional[str] = None) -> str:
        
        if not filename:
            filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = self.log_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.packet_log, f, indent=2, default=str)
        
        logger.info(f"Packets exported to {filepath}")
        return str(filepath)
    
    def export_packets_to_csv(self, filename: Optional[str] = None) -> str:
        
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
        
        if not filename:
            filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = self.log_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.alert_log, f, indent=2, default=str)
        
        logger.info(f"Alerts exported to {filepath}")
        return str(filepath)
    
    def generate_summary_report(self) -> Dict:
        
        return {
            "report_time": datetime.now().isoformat(),
            "total_packets": len(self.packet_log),
            "total_alerts": len(self.alert_log),
            "total_statistics_snapshots": len(self.statistics_log),
        }
    
    def export_html_report(self, stats: Dict, alerts: List[Dict], 
                          filename: Optional[str] = None) -> str:
        
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
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Report</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
                .container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                h1 { border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 30px; }
                h2 { margin-top: 30px; color: #444; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
                .stat-card { background: #f8f9fa; padding: 20px; border-radius: 6px; border: 1px solid #eee; }
                .stat-value { font-size: 24px; font-weight: bold; color: #2196f3; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
                th { background: #f8f9fa; }
                .alert-critical { color: #d32f2f; }
                .alert-warning { color: #f57c00; }
                .alert-info { color: #0288d1; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Network Traffic Report</h1>
                <p>Generated on: {timestamp}</p>
                
                <div class="grid">
                    <div class="stat-card">
                        <div class="stat-label">Total Packets</div>
                        <div class="stat-value">{total_packets}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Total Volume</div>
                        <div class="stat-value">{total_bytes} bytes</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Bandwidth</div>
                        <div class="stat-value">{bandwidth} Mbps</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Avg Packet Size</div>
                        <div class="stat-value">{avg_size} bytes</div>
                    </div>
                </div>
                
                <h2>Protocol Distribution</h2>
                <table>
                    <thead>
                        <tr><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Percentage</th></tr>
                    </thead>
                    <tbody>
                        {protocol_rows}
                    </tbody>
                </table>
                
                <h2>Security Alerts ({alert_count})</h2>
                <div>
                    {alert_rows}
                </div>
            </div>
        </body>
        </html>
        """
        
        protocol_rows = ""
        for proto, data in stats.get('protocol_distribution', {}).items():
            percentage = data.get('percentage', 0)
            protocol_rows += f"<tr><td>{proto}</td><td>{data.get('count', 0)}</td><td>{data.get('bytes', 0)}</td><td>{percentage:.1f}%</td></tr>"
        
        alert_rows = ""
        if alerts:
            alert_rows = "<table><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Details</th></tr></thead><tbody>"
            for alert in alerts[:50]:
                severity_class = f"alert-{alert.get('severity', 'info')}"
                alert_rows += f"<tr class='{severity_class}'><td>{alert.get('timestamp')}</td><td>{alert.get('type')}</td><td>{alert.get('severity')}</td><td>{alert.get('source_ip')} -> {alert.get('dest_ip')}</td></tr>"
            alert_rows += "</tbody></table>"
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
        
        self.packet_log.clear()
        self.statistics_log.clear()
        self.alert_log.clear()
        logger.info("All logs cleared")
