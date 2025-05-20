#!/usr/bin/env python3
# Network Scanner - Discovers devices on local networks
# This tool scans networks for connected devices and provides information
# about IP address, MAC address, vendor, and device fingerprinting

import sys
import subprocess
import socket
import time
import re
import json
import csv
import argparse
from datetime import datetime
from pathlib import Path
import concurrent.futures
import urllib.request
import ipaddress

try:
    import scapy.all as scapy
except ImportError:
    print("[!] Scapy library not found. Installing...")
    subprocess.call([sys.executable, "-m", "pip", "install", "scapy"])
    import scapy.all as scapy

try:
    import netifaces
except ImportError:
    print("[!] Netifaces library not found. Installing...")
    subprocess.call([sys.executable, "-m", "pip", "install", "netifaces"])
    import netifaces

# Global constants
MAC_DB_FILE = "mac_vendors.csv"
FINGERPRINT_DB_FILE = "device_fingerprints.json"
NMAP_SIGNATURES_FILE = "nmap-os-db.json"
MAX_WORKERS = 50
SCAN_TIMEOUT = 3  # seconds
PORT_SCAN_TIMEOUT = 1  # seconds for port scanning

# Common ports to scan for fingerprinting
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 
    143, 389, 443, 445, 548, 587, 631, 873, 993, 995, 
    1080, 1433, 1521, 1723, 1883, 2049, 2222, 2375, 
    3306, 3389, 5222, 5432, 5900, 6379, 7001, 8000, 
    8080, 8081, 8443, 8883, 9000, 9090, 9100, 9200
]

# Device type patterns based on open ports, banner and hostname
DEVICE_TYPE_PATTERNS = {
    "router": ["router", "gateway", "modem", "admin", "wifi", "ubnt", "tp-link", "dlink", "asus", "huawei", "netgear", "mikrotik", "linksys", "gateway.2wire.net", "livebox"],
    "printer": ["printer", "hp", "epson", "canon", "xerox", "lexmark", "brother", "kyocera", "9100", "515", "631"],
    "camera": ["camera", "webcam", "ipcam", "hikvision", "dahua", "axis", "netcam", "avigilon", "foscam", "554", "rtsp"],
    "media": ["media", "dlna", "sonos", "bose", "chromecast", "appletv", "roku", "firestick", "kodi", "plex", "8008", "8009"],
    "iot": ["smart", "iot", "nest", "hue", "ring", "echo", "alexa", "google home", "automation", "zwave", "zigbee"],
    "nas": ["nas", "synology", "qnap", "wd", "asustor", "drobo", "readynas", "truenas", "freenas", "445", "139"],
    "server": ["server", "ubuntu", "centos", "debian", "redhat", "windows server", "linux", "apache", "nginx", "iis", "444", "8443"],
    "game_console": ["playstation", "xbox", "nintendo", "ps4", "ps5", "nswitch", "game"],
    "tv": ["tv", "samsung", "lg", "sony", "vizio", "hisense", "television", "smarttv"],
    "voice_assistant": ["echo", "alexa", "google home", "homepod", "assistant"],
    "mobile": ["iphone", "android", "phone", "mobile", "ipad", "tablet", "samsung galaxy"],
    "desktop": ["pc", "desktop", "laptop", "computer", "windows", "mac", "linux"],
    "virtual_machine": ["vm", "virtual", "kvm", "hypervisor", "vmware", "virtualbox", "proxmox", "docker"],
}

class NetworkScanner:
    def __init__(self, args):
        self.args = args
        self.mac_vendors = {}
        self.fingerprint_db = {}
        self.os_signatures = {}
        self.network_interfaces = []
        self.current_network = None
        self.scan_results = {}
        self.total_devices = 0
    
    def setup(self):
        """Initialize scanner and necessary data files"""
        print("[*] Starting Network Scanner setup...")
        
        # Load MAC vendor database
        self.load_mac_vendors()
        
        # Load fingerprint database
        self.load_fingerprint_database()
        
        # Get all network interfaces
        self.get_network_interfaces()
        
        if not self.network_interfaces:
            print("[!] No suitable network interfaces found.")
            sys.exit(1)

    def load_mac_vendors(self):
        """Load or download MAC vendor database"""
        db_path = Path(MAC_DB_FILE)
        
        if not db_path.exists() or self.args.update_db:
            print("[*] MAC vendor database not found or update requested. Downloading...")
            try:
                url = "https://standards-oui.ieee.org/oui/oui.csv"
                print(f"[*] Downloading MAC vendor database from {url}")
                
                with urllib.request.urlopen(url) as response, open(db_path, 'wb') as out_file:
                    data = response.read()
                    out_file.write(data)
                print("[+] MAC vendor database downloaded successfully")
            except Exception as e:
                print(f"[!] Error downloading MAC vendor database: {e}")
                print("[*] Creating empty MAC vendor database")
                with open(db_path, 'w') as f:
                    f.write("Registry,Assignment,Organization Name,Organization Address\n")
        
        # Load the MAC database
        try:
            print("[*] Loading MAC vendor database...")
            with open(db_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 3:
                        # Format: Registry,Assignment,Organization Name,...
                        mac_prefix = row[1].strip().replace('-', ':').lower()
                        vendor = row[2].strip()
                        if mac_prefix and vendor:
                            self.mac_vendors[mac_prefix.lower()] = vendor
            print(f"[+] Loaded {len(self.mac_vendors)} MAC vendor entries")
        except Exception as e:
            print(f"[!] Error loading MAC vendor database: {e}")

    def load_fingerprint_database(self):
        """Load or create device fingerprint database"""
        fp_path = Path(FINGERPRINT_DB_FILE)
        
        if not fp_path.exists():
            print("[*] Creating device fingerprint database...")
            # Create a basic fingerprint database
            self.fingerprint_db = {
                "ports": {
                    "80": ["Web Server", "Router", "IoT Device"],
                    "443": ["Secure Web Server", "Router", "IoT Device"],
                    "22": ["SSH Server", "Router", "Linux Device"],
                    "23": ["Telnet Server", "Router", "IoT Device"],
                    "21": ["FTP Server"],
                    "53": ["DNS Server"],
                    "25": ["SMTP Server"],
                    "110": ["POP3 Server"],
                    "143": ["IMAP Server"],
                    "445": ["SMB Server", "Windows Device", "NAS"],
                    "3389": ["RDP Server", "Windows Device"],
                    "5900": ["VNC Server"],
                    "8080": ["Web Server", "Proxy"],
                    "8443": ["Secure Web Server"],
                    "9100": ["Printer"],
                    "515": ["Printer"],
                    "631": ["IPP Printer"],
                    "548": ["AFP Server", "Mac Device"],
                    "8009": ["Chromecast"],
                    "1883": ["MQTT Broker", "IoT Device"],
                    "5222": ["XMPP Server"],
                    "1900": ["UPnP Device", "Smart TV", "Media Device"],
                    "8008": ["Smart TV", "Chromecast"],
                    "554": ["RTSP", "IP Camera"],
                },
                "banners": {
                    "SSH": {
                        "OpenSSH": "Linux/Unix",
                        "dropbear": "Embedded Linux",
                        "cisco": "Cisco Device",
                        "mikrotik": "MikroTik Router"
                    },
                    "HTTP": {
                        "Apache": "Web Server",
                        "nginx": "Web Server",
                        "Microsoft-IIS": "Windows Web Server",
                        "lighttpd": "Web Server",
                        "mini_httpd": "Embedded Web Server"
                    }
                }
            }
            
            # Save the database
            with open(fp_path, 'w') as f:
                json.dump(self.fingerprint_db, f, indent=2)
        else:
            # Load the database
            try:
                with open(fp_path, 'r') as f:
                    self.fingerprint_db = json.load(f)
            except Exception as e:
                print(f"[!] Error loading fingerprint database: {e}")
                self.fingerprint_db = {"ports": {}, "banners": {}}

    def get_network_interfaces(self):
        """Get list of available network interfaces"""
        try:
            # Get all interfaces
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                # Skip loopback interface and virtual interfaces
                if iface == "lo" or iface.startswith(("vbox", "vmnet", "docker", "veth", "br-")):
                    continue
                
                # Get interface addresses
                if netifaces.AF_INET in netifaces.ifaddresses(iface):
                    ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
                    if 'addr' in ip_info and 'netmask' in ip_info:
                        ip = ip_info['addr']
                        
                        if ip == '127.0.0.1':
                            continue
                        
                        # Calculate network address and CIDR
                        netmask = ip_info['netmask']
                        cidr = self.netmask_to_cidr(netmask)
                        network = f"{ip}/{cidr}"
                        
                        # Add interface to list
                        self.network_interfaces.append({
                            "name": iface,
                            "ip": ip,
                            "netmask": netmask,
                            "cidr": cidr,
                            "network": network
                        })
                
        except Exception as e:
            print(f"[!] Error getting network interfaces: {e}")

    def netmask_to_cidr(self, netmask):
        """Convert subnet mask to CIDR notation"""
        try:
            return sum([bin(int(x)).count('1') for x in netmask.split('.')])
        except:
            return 24  # Default fallback
    
    def select_network(self):
        """Let user select network to scan or scan all networks"""
        if self.args.network:
            # Use specified network
            self.current_network = self.args.network
            print(f"[*] Using specified network: {self.current_network}")
            return True
        elif self.args.interface:
            # Find network for specified interface
            for iface in self.network_interfaces:
                if iface["name"] == self.args.interface:
                    self.current_network = iface["network"]
                    print(f"[*] Using network {self.current_network} from interface {iface['name']}")
                    return True
            print(f"[!] Interface {self.args.interface} not found or has no IPv4 address")
            return False
        elif self.args.scan_all:
            # Scan all networks sequentially
            print("[*] Will scan all available networks")
            return True
        else:
            # Interactive selection
            if len(self.network_interfaces) == 1:
                # Only one interface, use it
                self.current_network = self.network_interfaces[0]["network"]
                print(f"[*] Using the only available network: {self.current_network}")
                return True
            
            # Let user choose
            print("\n[?] Select network to scan:")
            print("    0. Scan all networks")
            for idx, iface in enumerate(self.network_interfaces, 1):
                print(f"    {idx}. {iface['name']}: {iface['network']}")
            
            choice = -1
            while choice < 0 or choice > len(self.network_interfaces):
                try:
                    choice = int(input("\nEnter your choice (0-{}): ".format(len(self.network_interfaces))))
                except ValueError:
                    continue
            
            if choice == 0:
                print("[*] Will scan all available networks")
                self.args.scan_all = True
                return True
            else:
                self.current_network = self.network_interfaces[choice-1]["network"]
                print(f"[*] Selected network: {self.current_network}")
                return True
    
    def lookup_mac_vendor(self, mac_address):
        """Look up vendor in MAC database"""
        if not mac_address:
            return "Unknown"
        
        # Try different prefix lengths
        mac = mac_address.lower().replace(':', '').replace('-', '')
        
        # Check 6-byte prefix (OUI)
        prefix = mac[:6]
        if prefix in self.mac_vendors:
            return self.mac_vendors[prefix]
        
        return "Unknown"

    def arp_scan(self, network):
        """Perform ARP scan to discover devices"""
        print(f"[*] Performing ARP scan on network {network}...")
        
        try:
            # Create ARP request for all hosts in network
            arp_request = scapy.ARP(pdst=network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request
            
            # Send and receive responses
            result = scapy.srp(packet, timeout=SCAN_TIMEOUT, verbose=0)[0]
            
            # Process responses
            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self.lookup_mac_vendor(received.hwsrc),
                    'hostname': '',
                    'device_type': '',
                    'open_ports': [],
                    'os': 'Unknown',
                    'ports': {}
                })
            
            print(f"[+] ARP scan found {len(devices)} devices on network {network}")
            return devices
            
        except Exception as e:
            print(f"[!] Error during ARP scan on {network}: {e}")
            return []

    def ping_scan(self, network):
        """Perform ICMP ping scan as fallback method"""
        print(f"[*] Performing ping scan on network {network}...")
        
        try:
            # Parse network to get range of IPs
            net = ipaddress.IPv4Network(network, strict=False)
            devices = []
            
            # Use thread pool for parallel scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Submit ping tasks
                futures = {executor.submit(self.ping_host, str(ip)): str(ip) for ip in net.hosts()}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    try:
                        is_up, mac = future.result()
                        if is_up:
                            devices.append({
                                'ip': ip,
                                'mac': mac,
                                'vendor': self.lookup_mac_vendor(mac),
                                'hostname': '',
                                'device_type': '',
                                'open_ports': [],
                                'os': 'Unknown',
                                'ports': {}
                            })
                    except Exception as e:
                        print(f"[!] Error pinging {ip}: {e}")
            
            print(f"[+] Ping scan found {len(devices)} devices on network {network}")
            return devices
            
        except Exception as e:
            print(f"[!] Error during ping scan on {network}: {e}")
            return []

    def ping_host(self, ip):
        """Ping individual host and get MAC address if available"""
        try:
            # Different commands for different platforms
            if sys.platform == 'win32':
                ping_cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            # Execute ping command
            result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            
            # Check if host is up
            is_up = result.returncode == 0
            
            # Get MAC address from ARP table if host is up
            mac = "Unknown"
            if is_up:
                mac = self.get_mac_from_ip(ip)
            
            return is_up, mac
            
        except Exception:
            return False, "Unknown"

    def get_mac_from_ip(self, ip):
        """Get MAC address from IP using ARP table"""
        try:
            # Different commands for different platforms
            if sys.platform == 'win32':
                arp_cmd = ["arp", "-a", ip]
                pattern = r"([0-9a-fA-F]{2}[-:]){5}([0-9a-fA-F]{2})"
            elif sys.platform == 'darwin':  # macOS
                arp_cmd = ["arp", "-n", ip]
                pattern = r"([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2})"
            else:  # Linux
                arp_cmd = ["arp", "-n", ip]
                pattern = r"([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2})"
            
            # Execute ARP command
            result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
            
            # Extract MAC address using regex
            match = re.search(pattern, result.stdout)
            if match:
                return match.group(0)
            
            return "Unknown"
            
        except Exception:
            return "Unknown"

    def resolve_hostnames(self, devices):
        """Try to resolve hostnames for discovered devices"""
        print("[*] Resolving hostnames...")
        
        for device in devices:
            try:
                hostname = socket.getfqdn(device['ip'])
                if hostname != device['ip']:  # Only update if a real hostname was found
                    device['hostname'] = hostname
            except:
                pass  # Keep it empty if resolution fails
        
        print("[+] Hostname resolution completed")
        return devices

    def scan_device_ports(self, devices):
        """Scan common ports on devices for fingerprinting"""
        if not self.args.port_scan:
            print("[*] Port scanning disabled, skipping...")
            return devices
        
        print(f"[*] Scanning ports on {len(devices)} devices...")
        
        # Use thread pool for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Create tasks for each device
            for device in devices:
                executor.submit(self.scan_ports, device)
        
        print("[+] Port scanning completed")
        return devices

    def scan_ports(self, device):
        """Scan ports on a single device"""
        ip = device['ip']
        ports_dict = {}
        open_ports = []
        
        print(f"[*] Scanning ports on {ip}...")
        
        # Use thread pool for parallel port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            # Submit port scanning tasks
            futures = {executor.submit(self.check_port, ip, port): port for port in COMMON_PORTS}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        open_ports.append(port)
                        ports_dict[str(port)] = {
                            "banner": banner,
                            "service": self.identify_service(port, banner)
                        }
                except Exception:
                    pass
        
        device['open_ports'] = open_ports
        device['ports'] = ports_dict
        
        # Update device type based on open ports
        self.fingerprint_device(device)
        
        return device

    def check_port(self, ip, port):
        """Check if a specific port is open and try to get banner"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            
            # Try to connect
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port is open, try to get banner
                banner = self.get_banner(sock, port)
                sock.close()
                return True, banner
            else:
                sock.close()
                return False, ""
                
        except Exception:
            return False, ""

    def get_banner(self, sock, port):
        """Try to get service banner from open port"""
        banner = ""
        try:
            # Send different probes based on port
            if port in [80, 443, 8080, 8443]:
                # HTTP probe
                request = "HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: NetworkScanner\r\n\r\n"
                sock.send(request.encode())
            elif port == 22:
                # SSH usually sends banner automatically
                pass
            elif port == 21:
                # FTP usually sends banner automatically
                pass
            elif port == 25:
                # SMTP usually sends banner automatically
                pass
            elif port == 23:
                # Telnet usually sends banner automatically
                pass
            else:
                # Generic probe
                sock.send(b"\r\n")
            
            # Set short timeout for banner grabbing
            sock.settimeout(1)
            
            # Try to receive data
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
        except Exception:
            pass
            
        return banner

    def identify_service(self, port, banner):
        """Identify service based on port and banner"""
        # Common port to service mapping
        port_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Proxy",
            9100: "Printer"
        }
        
        # Check if port is in our mapping
        if port in port_services:
            service = port_services[port]
        else:
            service = f"Unknown-{port}"
        
        # Use banner to refine service identification
        if banner:
            lower_banner = banner.lower()
            if "ssh" in lower_banner:
                service = "SSH"
            elif "ftp" in lower_banner:
                service = "FTP"
            elif "smtp" in lower_banner:
                service = "SMTP"
            elif "http" in lower_banner:
                if "200 ok" in lower_banner or "404 not found" in lower_banner or "301 moved" in lower_banner:
                    service = "HTTP" if port != 443 else "HTTPS"
                if "server:" in lower_banner:
                    match = re.search(r"server: ([^\r\n]+)", lower_banner, re.IGNORECASE)
                    if match:
                        service += f" ({match.group(1).strip()})"
            elif "pop3" in lower_banner:
                service = "POP3"
            elif "imap" in lower_banner:
                service = "IMAP"
            elif "rdp" in lower_banner or "microsoft terminal services" in lower_banner:
                service = "RDP"
            elif "vnc" in lower_banner:
                service = "VNC"
            elif "printer" in lower_banner or "ready to print" in lower_banner:
                service = "Printer"
        
        return service

    def fingerprint_device(self, device):
        """Fingerprint device based on open ports, banners, and other data"""
        # Start with an empty list of possible device types
        possible_types = []
        
        # Check open ports against known patterns
        for port in device['open_ports']:
            port_str = str(port)
            if port_str in self.fingerprint_db.get("ports", {}):
                possible_types.extend(self.fingerprint_db["ports"][port_str])
        
        # Check service banners
        for port, port_info in device['ports'].items():
            banner = port_info.get("banner", "").lower()
            service = port_info.get("service", "").lower()
            
            # Check for specific service banners
            if "ssh" in service:
                for key, device_type in self.fingerprint_db.get("banners", {}).get("SSH", {}).items():
                    if key.lower() in banner:
                        possible_types.append(device_type)
            
            if "http" in service:
                for key, device_type in self.fingerprint_db.get("banners", {}).get("HTTP", {}).items():
                    if key.lower() in banner:
                        possible_types.append(device_type)
        
        # Check hostname for clues
        hostname = device.get('hostname', '').lower()
        if hostname:
            for device_type, patterns in DEVICE_TYPE_PATTERNS.items():
                for pattern in patterns:
                    if pattern in hostname:
                        possible_types.append(device_type.replace('_', ' ').title())
        
        # Check vendor for additional clues
        vendor = device.get('vendor', '').lower()
        if "apple" in vendor:
            possible_types.append("Apple Device")
        elif "tp-link" in vendor or "netgear" in vendor or "linksys" in vendor or "dlink" in vendor or "cisco" in vendor:
            possible_types.append("Network Device")
        elif "raspberry" in vendor:
            possible_types.append("Raspberry Pi")
        elif "sonos" in vendor:
            possible_types.append("Smart Speaker")
        elif "xbox" in vendor:
            possible_types.append("Game Console")
        elif "playstation" in vendor:
            possible_types.append("Game Console")
        elif "nintendo" in vendor:
            possible_types.append("Game Console")
        elif "samsung" in vendor and 445 not in device['open_ports']:
            possible_types.append("Smart TV")
        
        # Make educated guess about OS
        os_guess = "Unknown"
        if 3389 in device['open_ports']:
            os_guess = "Windows"
        elif 22 in device['open_ports'] and 445 not in device['open_ports']:
            os_guess = "Linux/Unix"
        elif 548 in device['open_ports'] or 5009 in device['open_ports']:
            os_guess = "macOS"
        elif 80 in device['open_ports'] and 21 in device['open_ports'] and 23 in device['open_ports']:
            os_guess = "Embedded OS"
        
        device['os'] = os_guess
        
        # Count occurrences of each type and take the most common ones
        type_counts = {}
        for t in possible_types:
            type_counts[t] = type_counts.get(t, 0) + 1
        
        # Sort by count, then by name
        sorted_types = sorted(type_counts.items(), key=lambda x: (-x[1], x[0]))
        
        # Get the most likely type(s)
        top_types = []
        if sorted_types:
            max_count = sorted_types[0][1]
            for t, count in sorted_types:
                if count == max_count:
                    top_types.append(t)
                else:
                    break
        
        # Use the top types as the device type
        if top_types:
            device['device_type'] = ', '.join(top_types[:3])  # Limit to top 3
        else:
            # Default fallbacks based on basic indicators
            if device['vendor'] != 'Unknown':
                device['device_type'] = f"{device['vendor']} Device"
            else:
                device['device_type'] = "Unknown Device"
        
        return device

    def scan_network(self, network):
        """Scan a specific network for devices"""
        print(f"\n[*] Scanning network: {network}")
        
        # Track time for performance monitoring
        start_time = time.time()
        
        # Try ARP scan first (faster and more reliable)
        devices = self.arp_scan(network)
        
        # If ARP scan found nothing, try ping scan as fallback
        if not devices and self.args.ping_fallback:
            print("[*] ARP scan found no devices, trying ping scan...")
            devices = self.ping_scan(network)
        
        # Resolve hostnames if enabled
        devices = self.resolve_hostnames(devices)
        
        # Scan ports if enabled
        devices = self.scan_device_ports(devices)
        
        # Sort devices by IP address for consistent output
        devices.sort(key=lambda d: [int(octet) for octet in d['ip'].split('.')])
        
        # Store results for this network
        self.scan_results[network] = devices
        self.total_devices += len(devices)
        
        # Print summary
        scan_time = time.time() - start_time
        print(f"[+] Network scan completed in {scan_time:.2f} seconds")
        print(f"[+] Found {len(devices)} devices on network {network}")
        
        return devices

    def run(self):
        """Run the network scanner"""
        print("\n" + "=" * 60)
        print(" WhoIsHere - Find and fingerprint devices on your network")
        print("=" * 60)
        
        self.setup()
        
        # Select network to scan
        if not self.select_network():
            return
        
        start_time = time.time()
        
        if self.args.scan_all:
            # Scan all available networks
            for iface in self.network_interfaces:
                self.scan_network(iface["network"])
        else:
            # Scan single network
            self.scan_network(self.current_network)
        
        # Print overall summary
        total_time = time.time() - start_time
        print("\n" + "=" * 60)
        print(f"[+] Scan completed in {total_time:.2f} seconds")
        print(f"[+] Found a total of {self.total_devices} devices")
        print("=" * 60)
        
        # Display results
        self.display_results()
        
        # Save results if requested
        if self.args.output:
            self.save_results()

    def display_results(self):
        """Display scan results in a user-friendly format"""
        if not self.scan_results:
            print("[!] No scan results to display")
            return
        
        for network, devices in self.scan_results.items():
            print(f"\n[+] Network: {network} - {len(devices)} devices found")
            print("-" * 80)
            print(f"{'IP Address':<16} {'MAC Address':<18} {'Vendor':<25} {'Device Type':<25}")
            print("-" * 80)
            
            for device in devices:
                ip = device['ip']
                mac = device['mac']
                vendor = device['vendor'][:24] if device['vendor'] else "Unknown"  # Truncate if too long
                device_type = device['device_type'][:24] if device['device_type'] else "Unknown"  # Truncate if too long
                
                print(f"{ip:<16} {mac:<18} {vendor:<25} {device_type:<25}")
            
            # Print detailed information if verbose mode
            if self.args.verbose:
                print("\nDetailed Device Information:")
                for device in devices:
                    print("\n" + "-" * 80)
                    print(f"Device: {device['ip']} ({device['mac']})")
                    print(f"  Vendor: {device['vendor']}")
                    print(f"  Hostname: {device['hostname'] if device['hostname'] else 'N/A'}")
                    print(f"  Device Type: {device['device_type']}")
                    print(f"  OS: {device['os']}")
                    
                    if device['open_ports']:
                        print(f"  Open Ports: {', '.join(map(str, device['open_ports']))}")
                        print("  Services:")
                        for port, port_info in device['ports'].items():
                            banner = port_info.get('banner', '')
                            if len(banner) > 40:
                                banner = banner[:37] + "..."
                            print(f"    {port}/{port_info.get('service', 'unknown')}: {banner}")
                    else:
                        print("  No open ports found")

    def save_results(self):
        """Save scan results to file in specified format"""
        if not self.scan_results:
            print("[!] No scan results to save")
            return
        
        output_file = self.args.output
        
        # Determine output format from filename or default to JSON
        if output_file.lower().endswith('.json'):
            self.save_as_json(output_file)
        elif output_file.lower().endswith('.csv'):
            self.save_as_csv(output_file)
        elif output_file.lower().endswith('.html'):
            self.save_as_html(output_file)
        else:
            # Default to JSON if no recognized extension
            self.save_as_json(output_file + '.json')

    def save_as_json(self, filename):
        """Save results as JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump({
                    'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'total_devices': self.total_devices,
                    'networks': self.scan_results
                }, f, indent=2)
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving results to {filename}: {e}")

    def save_as_csv(self, filename):
        """Save results as CSV file"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['Network', 'IP Address', 'MAC Address', 'Vendor', 'Hostname', 
                                'Device Type', 'OS', 'Open Ports'])
                
                # Write data
                for network, devices in self.scan_results.items():
                    for device in devices:
                        writer.writerow([
                            network,
                            device['ip'],
                            device['mac'],
                            device['vendor'],
                            device['hostname'],
                            device['device_type'],
                            device['os'],
                            ', '.join(map(str, device['open_ports']))
                        ])
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving results to {filename}: {e}")

    def save_as_html(self, filename):
        """Save results as HTML file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Write HTML header
                f.write('''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2980b9; margin-top: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .details-btn { background-color: #3498db; color: white; border: none; padding: 5px 10px; cursor: pointer; }
        .details { display: none; margin: 10px 0 10px 20px; border-left: 3px solid #3498db; padding-left: 10px; }
        .summary { margin-bottom: 20px; background-color: #eaf2f8; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Network Scanner Report</h1>
    <div class="summary">
        <p><strong>Scan Time:</strong> ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
        <p><strong>Total Devices Found:</strong> ''' + str(self.total_devices) + '''</p>
    </div>
''')
                
                # Write data for each network
                for network, devices in self.scan_results.items():
                    f.write(f'''    <h2>Network: {network} ({len(devices)} devices)</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Vendor</th>
            <th>Hostname</th>
            <th>Device Type</th>
            <th>OS</th>
            <th>Open Ports</th>
            <th>Actions</th>
        </tr>
''')
                    
                    for i, device in enumerate(devices):
                        f.write(f'''        <tr>
            <td>{device['ip']}</td>
            <td>{device['mac']}</td>
            <td>{device['vendor']}</td>
            <td>{device['hostname'] if device['hostname'] else 'N/A'}</td>
            <td>{device['device_type']}</td>
            <td>{device['os']}</td>
            <td>{', '.join(map(str, device['open_ports'])) if device['open_ports'] else 'None'}</td>
            <td><button class="details-btn" onclick="toggleDetails('device-{i}')">Details</button></td>
        </tr>
        <tr>
            <td colspan="8">
                <div id="device-{i}" class="details">
                    <h4>Port Details:</h4>
''')
                        
                        if device['ports']:
                            f.write('                    <table>\n')
                            f.write('                        <tr><th>Port</th><th>Service</th><th>Banner</th></tr>\n')
                            for port, port_info in device['ports'].items():
                                banner = port_info.get('banner', '')
                                if len(banner) > 50:
                                    banner = banner[:47] + "..."
                                # Escape HTML special characters
                                banner = banner.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                                f.write(f'''                        <tr>
                            <td>{port}</td>
                            <td>{port_info.get('service', 'unknown')}</td>
                            <td>{banner}</td>
                        </tr>
''')
                            f.write('                    </table>\n')
                        else:
                            f.write('                    <p>No port details available</p>\n')
                        
                        f.write('''                </div>
            </td>
        </tr>
''')
                    
                    f.write('    </table>\n')
                
                # Write HTML footer with JavaScript for toggling details
                f.write('''
    <script>
        function toggleDetails(id) {
            var element = document.getElementById(id);
            element.style.display = element.style.display === "block" ? "none" : "block";
        }
    </script>
</body>
</html>
''')
            
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving results to {filename}: {e}")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Network Scanner - Discover and fingerprint devices on your network')
    
    # Network selection
    network_group = parser.add_argument_group('Network Selection')
    network_group.add_argument('-n', '--network', help='Network to scan (CIDR notation, e.g. 192.168.1.0/24)')
    network_group.add_argument('-i', '--interface', help='Network interface to scan')
    network_group.add_argument('-a', '--scan-all', action='store_true', help='Scan all available networks')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-p', '--port-scan', action='store_true', help='Perform port scanning for fingerprinting')
    scan_group.add_argument('-r', '--resolve-names', action='store_true', help='Resolve hostnames for discovered devices')
    scan_group.add_argument('--ping-fallback', action='store_true', help='Use ping scan as fallback if ARP scan fails')
    scan_group.add_argument('--update-db', action='store_true', help='Update MAC vendor database')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', help='Save results to file (supported formats: json, csv, html)')
    output_group.add_argument('-v', '--verbose', action='store_true', help='Show detailed information for each device')
    
    return parser.parse_args()


def main():
    """Main function"""
    # Parse command line arguments
    args = parse_arguments()
    
    try:
        # Create scanner
        scanner = NetworkScanner(args)
        
        # Run scanner
        scanner.run()
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()