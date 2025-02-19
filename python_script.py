import os
import sys
import ipaddress
import socket

def expand_ip_ranges(ip_ranges):
    """Expand IP ranges into individual IP addresses."""
    ip_addresses = {}
    for ip_range in ip_ranges:
        try:
            ip_address, netmask = ip_range.split('/')
            netmask = int(netmask)
            networks = [ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)]
            ip_addresses.update({ip for network in networks for ip in network})
        except ValueError:
            print(f"Warning: Invalid IP range {ip_range}. Skipping...")
    return ip_addresses

def normalize_ip_range(ip_range):
    """Normalize an IP range to a standard format."""
    # Remove any existing CIDR notation
    ip_range = ip_range.rstrip('/')
    # Add a leading IP address
    ip_range = f"{ip_range}/24"
    return ip_range

def check_port_status(ip_addresses, target_ports):
    """Check if ports are open for each IP address."""
    open_ports = {}
    for ip_address in ip_addresses:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                for port in target_ports:
                    s.connect((ip_address, port))
                    open_ports[ip_address] = port
        except (socket.error, ipaddress.AddressValueError):
            pass
    return open_ports

def main():
    try:
        with open("ip/input.txt", "r") as f:
            ip_ranges = [line.strip() for line in f.readlines()]
        ip_addresses = expand_ip_ranges(ip_ranges)
        target_ports = [443, 80]
        open_ports = check_port_status(ip_addresses, target_ports)
        with open("ip/list.txt", "w") as f:
            for ip_address, port in open_ports.items():
                f.write(f"{ip_address}:{port}\n")
    except FileNotFoundError:
        print(f"Input file 'ip/input.txt' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
