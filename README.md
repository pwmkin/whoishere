# WhoIsHere  

An advanced network scanning tool written in Python that discovers devices on local networks and identifies their characteristics.  

## Features  

- 🔍 **Device discovery** using multiple techniques (ARP and ping)  
- 📋 **Device fingerprinting** to identify type, operating system, and other details  
- 🔎 **Port scanning** to identify running services  
- 📝 **Hostname resolution** for better device identification  
- 📊 **Manufacturer identification** based on MAC addresses  
- 💾 **Export results** in JSON, CSV, or HTML format  
- 🔄 **Offline database** for use without an internet connection  

## Requirements  

- Python 3.6 or higher  
- Libraries: scapy, netifaces  

### Additional Setup (Linux)

If you're using a Linux-based system and encounter issues when installing dependencies (especially `netifaces`), you may need to install additional development tools and headers:

#### Ubuntu/Debian:

```bash
sudo apt update
sudo apt install python3-dev build-essential
```

#### Fedora/RHEL/CentOS:

```bash
sudo dnf install python3-devel gcc
```

#### Arch Linux:

```bash
sudo pacman -S python
```

These packages are required to compile certain dependencies from source, especially those using C extensions.

## Installation  

```bash  
# Clone the repository  
git clone https://github.com/pwmkin/whoishere.git  
cd whoishere  

# Install dependencies  
pip install -r requirements.txt  
```  

Dependencies will be automatically installed when running the script if they are not available.  

## Usage  

### Basic execution  

```bash  
python whoishere.py  
```  

This will run the scanner in interactive mode, allowing you to select the network to scan.  

### Command line options  

```plaintext
Network selection options:  
  -n, --network NETWORK     Network to scan (CIDR notation, e.g., 192.168.1.0/24)  
  -i, --interface INTERFACE Network interface to scan  
  -a, --scan-all            Scan all available networks  

Scan options:  
  -p, --port-scan           Perform port scanning for fingerprinting  
  -r, --resolve-names       Resolve hostnames for discovered devices  
  --ping-fallback           Use ping scan as a fallback if ARP fails  
  --update-db               Update MAC vendor database  

Output options:  
  -o, --output OUTPUT       Save results to a file (formats: json, csv, html)  
  -v, --verbose             Show detailed information for each device  
```  

### Usage examples  

Scan a specific network with all features enabled:  

```bash  
python whoishere.py -n 192.168.1.0/24 -p -r -v  
```  

Scan a specific interface and save results in HTML:  

```bash  
python whoishere.py -i eth0 -p -o results.html  
```  

Scan all available networks:  

```bash  
python whoishere.py -a -p  
```  

Update the MAC vendor database:  

```bash  
python whoishere.py --update-db  
```  

## How It Works  

The scanner uses a combination of techniques to discover and fingerprint devices:  

1. **ARP Scan**: Primary and fastest method to discover devices on the local network  
2. **Ping Scan**: Alternative method when ARP fails to find devices  
3. **Hostname Resolution**: Attempts to obtain hostnames for devices  
4. **Port Scanning**: Scans common ports to identify services  
5. **Fingerprinting**: Uses collected information to determine device type and operating system  
6. **Vendor Identification**: Uses the OUI database to identify manufacturers from MAC addresses  

## Limitations  

- ARP scanning only works on local networks (same network segment)  
- Some routers/firewalls may block scanning  
- Fingerprinting accuracy depends on the amount of information that can be gathered  

## Security Notes  

This tool is intended for use exclusively on networks you own or with explicit authorization. Unauthorized network scanning may be illegal in some jurisdictions.  

## License  

This project is licensed under the MIT License.
