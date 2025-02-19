import os
import sys
import ipaddress
import socket

def expand_ip_ranges(ip_ranges):
    """Expand IP ranges into individual IP addresses."""
    ip_addresses = {}
    for ip_range in ip_ranges:
        try:
            networks = [ipaddress.ip_network(range, strict=False) for range in ip_range.split('/')]
            ip_addresses.update(network for network in networks for ip in network)
        except ValueError:
            print(f"Warning: Invalid IP range {ip_range}. Skipping...")
    return ip_addresses

def check_port_status(ip_addresses, target_ports):
    """Check if ports are open for each IP address."""
    open_ports = {}
    for ip_address in ip_addresses:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                for port, port_number in zip(target_ports, [443, 80]):
                    s.connect((ip_address, port))
                    open_ports[ip_address] = port_number
        except (socket.error, ipaddress.AddressValueError):
            pass
    return open_ports

def main():
    input_file = 'ip/input.txt'
    output_file = 'ip/list.txt'
    open_file = 'ip/open.txt'

    try:
        with open(input_file, 'r') as f:
            ip_ranges = [line.strip() for line in f.readlines()]
        ip_addresses = expand_ip_ranges(ip_ranges)
        target_ports = [443, 80]
        open_ports = check_port_status(ip_addresses, target_ports)
        with open(open_file, 'w') as f:
            for ip_address, port_number in open_ports.items():
                f.write(f"{ip_address}:{port_number}\n")
    except FileNotFoundError:
        print(f"Input file '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
