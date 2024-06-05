import os
import psutil
import socket
import requests
import subprocess
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "90198acc-b4a1-44ad-b704-082b61df598c"  # Your NVD API key

# Step 1: Get the IP address of the device
def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

# Step 2: Get the current network information
def get_network_info():
    net_info = psutil.net_if_addrs()
    return net_info

# Get the active network interface
def get_active_network_interface():
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return interface
    return None

# Step 3: Ping an IP address to check if it is active
def is_active_ip(ip_to_check):
    try:
        output = subprocess.check_output(["ping", "-n", "1", "-w", "1000", ip_to_check], universal_newlines=True)
        if "TTL=" in output:
            return True
    except subprocess.CalledProcessError:
        return False
    return False

# Step 4: Scan/ping for other IPs on the same network
def scan_ip(ip_to_check):
    if is_active_ip(ip_to_check):
        try:
            socket.gethostbyaddr(ip_to_check)
            return ip_to_check
        except socket.herror:
            return None
    return None

def scan_network(ip):
    ip_range = '.'.join(ip.split('.')[:-1]) + '.'
    devices = []

    with ThreadPoolExecutor(max_workers=100) as executor:  # Increased from 50 to 100
        futures = [executor.submit(scan_ip, ip_range + str(i)) for i in range(1, 255)]
        for future in tqdm(as_completed(futures), total=254, desc="Scanning network", unit=" IP"):
            result = future.result()
            if result:
                devices.append({'ip': result})

    return devices

# Step 5: Port scan confirmed IPs and check for vulnerable ports
def port_scan(ip, device_name):
    open_ports = []
    vulnerabilities = {}
    tqdm_desc = f"Scanning ports on {device_name} ({ip})"
    for port in tqdm(range(1, 1025), desc=tqdm_desc, unit=" port", leave=False):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.2)  # Reduced timeout for faster scanning
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
            cves = fetch_cves_for_port(port)
            if cves:
                vulnerabilities[port] = cves
        sock.close()
    return open_ports, vulnerabilities

def port_scan_ip(device):
    ip = device['ip']
    device_name = device['device_name']
    open_ports, vulnerabilities = port_scan(ip, device_name)
    return {'ip': ip, 'device_name': device_name, 'open_ports': open_ports, 'vulnerabilities': vulnerabilities}

# Step 6: Get device name
def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Step 7: Fetch CVE information from NVD API
def fetch_cves_for_port(port):
    params = {
        "keywordSearch": f"port {port}",
        "resultsPerPage": 5,
        "startIndex": 0
    }
    headers = {
        "apiKey": NVD_API_KEY  # Use the provided NVD API key
    }
    response = requests.get(NVD_API_URL, params=params, headers=headers)
    if response.status_code == 200:
        data = response.json()
        cve_items = data.get("vulnerabilities", [])
        cves = [item["cve"]["id"] for item in cve_items]
        return cves
    else:
        return []

# Step 8: Display the found valid IPs, device names, open ports, and vulnerabilities in a table in the console
def display_results(devices):
    table_data = []
    with ThreadPoolExecutor(max_workers=20) as executor:  # Increased from 10 to 20
        futures = [executor.submit(port_scan_ip, device) for device in devices]
        for future in tqdm(as_completed(futures), total=len(devices), desc="Processing devices", unit=" device"):
            result = future.result()
            if result:
                vuln_str = "; ".join([f"Port {port}: {', '.join(cves)}" for port, cves in result['vulnerabilities'].items()])
                table_data.append([
                    result['ip'],
                    result['device_name'],
                    ', '.join(map(str, result['open_ports'])),
                    vuln_str
                ])
            else:
                print(f"Failed to scan device: {device}")

    headers = ["IP Address", "Device Name", "Open Ports", "Vulnerabilities"]
    print(tabulate(table_data, headers, tablefmt="grid"))

# Function to display the table of found devices
def display_devices(devices):
    device_table = [[device['ip'], device['device_name']] for device in devices]
    headers = ["IP Address", "Device Name"]
    print(tabulate(device_table, headers, tablefmt="grid"))

def main():
    print("Ensure you have explicit permission from your IT department or network administrator to perform this scan.")
    consent = input("Do you have permission to perform this scan? (yes/no): ")
    if consent.lower() != 'yes':
        print("Permission not granted. Exiting.")
        return

    ip_address = get_ip_address()
    print(f"Device IP Address: {ip_address}")

    iface = get_active_network_interface()
    if iface is None:
        print("No active network interface found.")
        return

    print(f"Using network interface: {iface}")

    devices = scan_network(ip_address)
    for device in devices:
        device['device_name'] = get_device_name(device['ip'])

    print("Found Devices:")
    display_devices(devices)

    print("Starting port scanning and processing devices...")
    display_results(devices)

    # Pause the console to prevent it from closing automatically
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()