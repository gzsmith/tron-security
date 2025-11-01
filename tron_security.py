"""
TRON - Home Network Security System
A modular security monitoring program for home networks
"""

import scapy.all as scapy
from scapy.layers import http
import threading
import time
import json
import sqlite3
from datetime import datetime
from collections import defaultdict
import socket

class TronCore:
    """Core security engine for network monitoring"""
    
    def __init__(self, interface="enp0s3", db_path="/tmp/tron_security.db"):
        self.interface = interface
        self.db_path = db_path
        self.is_running = False
        self.monitored_devices = {}
        self.traffic_patterns = defaultdict(lambda: {"packets": 0, "bytes": 0, "last_seen": None})
        self.threat_log = []
        self.alert_callbacks = []
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for logging"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            
            # Create tables
            c.execute('''CREATE TABLE IF NOT EXISTS devices
                         (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, 
                          first_seen TEXT, last_seen TEXT, status TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS threats
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                          threat_type TEXT, source_ip TEXT, details TEXT, severity INTEGER)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS traffic_logs
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                          source_ip TEXT, dest_ip TEXT, protocol TEXT, packet_size INTEGER)''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[TRON] Database init error: {e}")
        
    def register_alert_callback(self, callback):
        """Register a callback function for alerts"""
        self.alert_callbacks.append(callback)
        
    def trigger_alert(self, alert_type, message, severity=1):
        """Trigger an alert to all registered callbacks"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "message": message,
            "severity": severity
        }
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Alert callback error: {e}")
        
        # Log to database
        self.log_threat(alert_type, message, severity)
        
    def log_threat(self, threat_type, details, severity, source_ip="unknown"):
        """Log threat to database"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            c.execute('''INSERT INTO threats (timestamp, threat_type, source_ip, details, severity)
                         VALUES (?, ?, ?, ?, ?)''',
                      (datetime.now().isoformat(), threat_type, source_ip, details, severity))
            conn.commit()
            conn.close()
        except Exception as e:
            pass
        
    def scan_network(self, ip_range="0.0.0.0/24"):
        """Scan network for active devices"""
        print(f"[TRON] Scanning network: {ip_range}")
        
        try:
            # Create ARP request
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send and receive packets with longer timeout
            answered_list = scapy.srp(arp_request_broadcast, timeout=10, verbose=False)[0]
            
            print(f"[DEBUG] Received {len(answered_list)} ARP responses")
            
            devices = []
            for element in answered_list:
                device = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "timestamp": datetime.now().isoformat()
                }
                devices.append(device)
                print(f"[TRON] Found device: {device['ip']} ({device['mac']})")
                self.update_device(device)
                
            return devices
            
        except Exception as e:
            print(f"[TRON] Network scan error: {e}")
            return []
    
    def update_device(self, device):
        """Update device information in database"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            
            # Check if device exists
            c.execute("SELECT * FROM devices WHERE mac=?", (device["mac"],))
            existing = c.fetchone()
            
            timestamp = datetime.now().isoformat()
            
            if existing:
                # Update last seen
                c.execute("UPDATE devices SET last_seen=?, ip=?, status='active' WHERE mac=?",
                         (timestamp, device["ip"], device["mac"]))
            else:
                # New device detected - potential alert
                try:
                    hostname = socket.gethostbyaddr(device["ip"])[0]
                except:
                    hostname = "Unknown"
                
                c.execute('''INSERT INTO devices (mac, ip, hostname, first_seen, last_seen, status)
                             VALUES (?, ?, ?, ?, ?, 'active')''',
                          (device["mac"], device["ip"], hostname, timestamp, timestamp))
                
                # Alert on new device
                self.trigger_alert(
                    "NEW_DEVICE",
                    f"New device detected: {device['ip']} ({device['mac']})",
                    severity=2
                )
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[TRON] Device update error: {e}")
        
    def packet_callback(self, packet):
        """Callback for processing captured packets"""
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                
                # Update traffic patterns
                key = f"{src_ip}->{dst_ip}"
                self.traffic_patterns[key]["packets"] += 1
                self.traffic_patterns[key]["bytes"] += len(packet)
                self.traffic_patterns[key]["last_seen"] = datetime.now()
                
                # Check for suspicious activity
                self.analyze_packet(packet)
                
        except Exception as e:
            pass  # Silently handle malformed packets
    
    def analyze_packet(self, packet):
        """Analyze packet for threats"""
        
        # Check for port scanning (multiple connections to different ports)
        if packet.haslayer(scapy.TCP):
            src_ip = packet[scapy.IP].src
            dst_port = packet[scapy.TCP].dport
            
            # Simple port scan detection (simplified for demo)
            if dst_port > 1024 and packet[scapy.TCP].flags == 2:  # SYN flag
                # Could implement more sophisticated detection here
                pass
        
        # Check for HTTP traffic (potential data exfiltration)
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            
            # Check against known malicious domains (simplified)
            suspicious_keywords = ['malware', 'phishing', 'exploit']
            if any(keyword in url.lower() for keyword in suspicious_keywords):
                self.trigger_alert(
                    "SUSPICIOUS_HTTP",
                    f"Suspicious HTTP request detected: {url}",
                    severity=3
                )
    
    def start_monitoring(self):
        """Start packet capture and monitoring"""
        self.is_running = True
        print(f"[TRON] Starting network monitoring on {self.interface}")
        
        try:
            # Start packet sniffing
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"[TRON] Monitoring error: {e}")
            self.is_running = False
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_running = False
        print("[TRON] Stopping network monitoring")
    
    def get_threat_summary(self):
        """Get summary of recent threats"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            c.execute('''SELECT threat_type, COUNT(*) as count, MAX(severity) as max_severity
                         FROM threats 
                         WHERE timestamp > datetime('now', '-24 hours')
                         GROUP BY threat_type''')
            threats = c.fetchall()
            conn.close()
            return threats
        except Exception as e:
            print(f"[TRON] Error getting threat summary: {e}")
            return []
    
    def get_active_devices(self):
        """Get list of active devices"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            c = conn.cursor()
            c.execute('''SELECT ip, mac, hostname, last_seen 
                         FROM devices 
                         WHERE status='active' 
                         ORDER BY last_seen DESC''')
            devices = c.fetchall()
            conn.close()
            return devices
        except Exception as e:
            print(f"[TRON] Error getting active devices: {e}")
            return []


class TronDashboard:
    """Simple text-based dashboard for Tron"""
    
    def __init__(self, tron_core):
        self.core = tron_core
        self.core.register_alert_callback(self.display_alert)
        
    def display_alert(self, alert):
        """Display alert in terminal"""
        severity_labels = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        severity = severity_labels.get(alert["severity"], "UNKNOWN")
        
        print(f"\n{'='*60}")
        print(f"[ALERT] {severity} - {alert['type']}")
        print(f"Time: {alert['timestamp']}")
        print(f"Message: {alert['message']}")
        print(f"{'='*60}\n")
    
    def display_status(self):
        """Display current system status"""
        print("\n" + "="*60)
        print("TRON SECURITY SYSTEM - STATUS DASHBOARD")
        print("="*60)
        
        # Active devices
        devices = self.core.get_active_devices()
        print(f"\nActive Devices: {len(devices)}")
        for device in devices[:5]:  # Show first 5
            print(f"  • {device[0]} ({device[1]}) - {device[2]}")
        
        # Recent threats
        threats = self.core.get_threat_summary()
        print(f"\nThreats (Last 24h): {sum(t[1] for t in threats)}")
        for threat in threats:
            print(f"  • {threat[0]}: {threat[1]} occurrences (Severity: {threat[2]})")
        
        print("\n" + "="*60 + "\n")


def main():
    """Main entry point for Tron Security System"""
    
    print("""
    ████████╗██████╗  ██████╗ ███╗   ██╗
    ╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
       ██║   ██████╔╝██║   ██║██╔██╗ ██║
       ██║   ██╔══██╗██║   ██║██║╚██╗██║
       ██║   ██║  ██║╚██████╔╝██║ ╚████║
       ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
    
    Home Network Security System v1.0
    """)
    
    # Initialize Tron with YOUR settings
    tron = TronCore(interface="enp0s3", db_path="/tmp/tron_security.db")
    dashboard = TronDashboard(tron)
    
    # Perform initial network scan
    print("[TRON] Performing initial network scan...")
    devices = tron.scan_network("0.0.0.0/24")
    print(f"[TRON] Found {len(devices)} devices")
    
    # Display initial status
    dashboard.display_status()
    
    # Start monitoring in background thread
    monitor_thread = threading.Thread(target=tron.start_monitoring, daemon=True)
    monitor_thread.start()
    
    # Periodic scanning and status updates
    try:
        print("[TRON] Monitoring active. Press Ctrl+C to stop.")
        while True:
            time.sleep(300)  # Scan every 5 minutes
            tron.scan_network("0.0.0.0/24")
            dashboard.display_status()
            
    except KeyboardInterrupt:
        print("\n[TRON] Shutting down...")
        tron.stop_monitoring()
        print("[TRON] Shutdown complete")


if __name__ == "__main__":
    main()

