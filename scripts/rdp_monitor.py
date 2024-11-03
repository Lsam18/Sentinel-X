import os
import json
import time
import logging
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
import requests
import win32evtlog
import win32security
import win32con

# Configuration
LOGFILE_NAME = "failed_rdp.log"
LOG_DIRECTORY = r"C:\ProgramData\RDPLogs"
BLOCKED_IP_DIRECTORY = r"C:\ProgramData\RDPLogs"
LOGFILE_PATH = os.path.join(LOG_DIRECTORY, LOGFILE_NAME)
BLOCKED_IPS_FILE = os.path.join(BLOCKED_IP_DIRECTORY, "blocked_ips.txt")

# System Information
def get_system_info():
    import socket
    import platform
    return {
        "ComputerName": socket.gethostname(),
        "Username": os.getenv("USERNAME"),
        "Domain": os.getenv("USERDOMAIN"),
        "IP": socket.gethostbyname(socket.gethostname()),
        "OSVersion": platform.platform()
    }

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class RDPMonitor:
    def __init__(self):
        self.failed_attempts = defaultdict(list)
        self.user_attempts = defaultdict(list)
        self.blocked_ips = set()
        self.processed_events = []
        self.ensure_directories()
        self.load_blocked_ips()

    def ensure_directories(self):
        """Create necessary directories if they don't exist"""
        os.makedirs(LOG_DIRECTORY, exist_ok=True)
        os.makedirs(BLOCKED_IP_DIRECTORY, exist_ok=True)
        if not os.path.exists(LOGFILE_PATH):
            self.write_sample_log()
        if not os.path.exists(BLOCKED_IPS_FILE):
            open(BLOCKED_IPS_FILE, 'a').close()

    def write_sample_log(self):
        """Write sample log entries"""
        sample_logs = [
            "latitude=47.91542,longitude=-120.60306,destinationhost=samplehost,username=fakeuser,sourcehost=24.16.97.222,state=Washington,country=United States,label=United States - 24.16.97.222,timestamp=2021-10-26 03:28:29",
            "latitude=-22.90906,longitude=-47.06455,destinationhost=samplehost,username=lnwbaq,sourcehost=20.195.228.49,state=Sao Paulo,country=Brazil,label=Brazil - 20.195.228.49,timestamp=2021-10-26 05:46:20"
        ]
        with open(LOGFILE_PATH, 'w', encoding='utf-8') as f:
            for log in sample_logs:
                f.write(f"{log}\n")

    def load_blocked_ips(self):
        """Load previously blocked IPs"""
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                self.blocked_ips = set(line.strip().split(': ')[1] for line in f if ': ' in line)

    def is_private_ip(self, ip):
        """Check if an IP address is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def block_ip(self, ip):
        """Block an IP address"""
        if ip not in self.blocked_ips:
            logging.warning(f"Blocking IP: {ip}")
            with open(BLOCKED_IPS_FILE, 'a') as f:
                f.write(f"Blocked IP: {ip}\n")
            self.blocked_ips.add(ip)
            # Here you would add actual firewall rules
            # Example: os.system(f'netsh advfirewall firewall add rule name="BLOCK IP {ip}" dir=in action=block remoteip={ip}')

    def is_outside_normal_hours(self, timestamp):
        """Check if the login attempt is outside normal business hours"""
        hour = timestamp.hour
        return hour < 8 or hour > 18

    def get_geolocation(self, ip):
        """Get geolocation information for an IP address"""
        if self.is_private_ip(ip):
            return {
                "latitude": "N/A",
                "longitude": "N/A",
                "state_prov": "Local Network",
                "country": "Local Network",
                "isp": "Local Network",
                "org": "Local Network"
            }

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,lat,lon,isp,org",
                timeout=5
            )
            data = response.json()
            
            if data.get("status") == "success":
                return {
                    "latitude": str(data.get("lat", "unknown")),
                    "longitude": str(data.get("lon", "unknown")),
                    "state_prov": data.get("regionName", "unknown"),
                    "country": data.get("country", "unknown"),
                    "isp": data.get("isp", "unknown"),
                    "org": data.get("org", "unknown")
                }
        except Exception as e:
            logging.error(f"Error getting geolocation for IP {ip}: {str(e)}")

        return {
            "latitude": "unknown",
            "longitude": "unknown",
            "state_prov": "unknown",
            "country": "unknown",
            "isp": "unknown",
            "org": "unknown"
        }

    def analyze_attack_pattern(self, source_ip, username, timestamp):
        """Analyze the attack pattern and determine the type"""
        current_time = datetime.now()
        
        # Track failed attempts
        self.failed_attempts[source_ip].append(current_time)
        self.user_attempts[username].append(current_time)
        
        # Clean up old attempts
        self.failed_attempts[source_ip] = [t for t in self.failed_attempts[source_ip] 
                                         if t >= current_time - timedelta(minutes=10)]
        self.user_attempts[username] = [t for t in self.user_attempts[username] 
                                      if t >= current_time - timedelta(minutes=30)]
        
        num_attempts = len(self.failed_attempts[source_ip])
        
        # Determine attack type
        if num_attempts >= 10:
            return "Advanced Brute Force", "Password Cracking - Brute Force (T1110.001)"
        elif len(self.user_attempts[username]) >= 5:
            return "Password Spraying", "Password Spraying (T1110.003)"
        elif self.is_outside_normal_hours(timestamp):
            return "Suspicious Time-Based Activity", "Application Layer Protocol - Suspicious Time (T1071)"
        
        return "Unknown", "Brute Force (T1110)"

    def process_event(self, event):
        """Process a single Windows security event"""
        try:
            # Extract event information
            timestamp = datetime.fromtimestamp(event.TimeGenerated)
            destination_host = event.ComputerName
            
            # Extract additional event data (modify based on your event structure)
            event_data = event.StringInsertions
            if not event_data or len(event_data) < 20:
                return
            
            username = event_data[5]
            source_ip = event_data[19]
            event_id = event.EventID
            logon_type = event_data[8]
            failure_reason = event_data[13]

            # Get geolocation data
            geo_data = self.get_geolocation(source_ip)
            
            # Analyze attack pattern
            attack_type, mitre_technique = self.analyze_attack_pattern(
                source_ip, username, timestamp
            )
            
            # Create log entry
            log_entry = (
                f"timestamp={timestamp.strftime('%Y-%m-%d %H:%M:%S')},"
                f"destinationhost={destination_host},username={username},"
                f"sourceip={source_ip},latitude={geo_data['latitude']},"
                f"longitude={geo_data['longitude']},state={geo_data['state_prov']},"
                f"country={geo_data['country']},isp={geo_data['isp']},"
                f"org={geo_data['org']},attacktype={attack_type},"
                f"mitreattacktechnique={mitre_technique},eventid={event_id},"
                f"logontype={logon_type},failurereason={failure_reason}"
            )

            # Write to log file
            with open(LOGFILE_PATH, 'a', encoding='utf-8') as f:
                f.write(f"{log_entry}\n")

            # Display event information
            self.display_event(timestamp, destination_host, username, source_ip,
                             geo_data, event_id, logon_type, failure_reason,
                             attack_type, mitre_technique)

            return True
        except Exception as e:
            logging.error(f"Error processing event: {str(e)}")
            return False

    def display_event(self, timestamp, destination_host, username, source_ip,
                     geo_data, event_id, logon_type, failure_reason,
                     attack_type, mitre_technique):
        """Display event information in a formatted way"""
        print("\n[EVENT DETECTED]")
        print(f"  Timestamp       : {timestamp}")
        print(f"  Destination Host: {destination_host}")
        print(f"  Username        : {username}")
        print(f"  Source IP       : {source_ip}")
        print(f"  Location        : {geo_data['country']}, {geo_data['state_prov']}")
        print(f"  ISP             : {geo_data['isp']}")
        print(f"  Organization    : {geo_data['org']}")
        print(f"  Event ID        : {event_id}")
        print(f"  Logon Type      : {logon_type}")
        print(f"  Failure Reason  : {failure_reason}")
        print(f"  Attack Type     : {attack_type}")
        print(f"  MITRE Technique : {mitre_technique}\n")

    def monitor_events(self):
        """Main monitoring loop"""
        handle = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        while True:
            try:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                
                for event in events:
                    if event.EventID == 4625:  # Failed login attempt
                        self.process_event(event)
                
                time.sleep(1)
            except Exception as e:
                logging.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(5)

def main():
    logging.info("Starting RDP Failed Login Monitor...")
    print(json.dumps(get_system_info(), indent=2))
    
    monitor = RDPMonitor()
    try:
        monitor.monitor_events()
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")

if __name__ == "__main__":
    main()