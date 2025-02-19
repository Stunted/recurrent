import ipaddress
import socket
import os

def expand_ip_range(line):
    """
    Expand a given IP, CIDR network, or IP range (start-end) into individual IP addresses.
    Returns a list of IP addresses (as strings).
    """
    ips = []
    line = line.strip()
    if not line:
        return ips

    # First try to parse as a single IP address.
    try:
        ip = ipaddress.ip_address(line)
        ips.append(str(ip))
        return ips
    except ValueError:
        pass

    # Next, if the line contains a slash, assume CIDR notation.
    if '/' in line:
        try:
            network = ipaddress.ip_network(line, strict=False)
            # Optionally include network and broadcast addresses.
            ips.append(str(network.network_address))
            # Include all hosts.
            ips.extend(str(ip) for ip in network.hosts())
            ips.append(str(network.broadcast_address))
            return ips
        except ValueError:
            pass

    # Finally, if the line contains a dash, assume an IP range "start-end".
    if '-' in line:
        try:
            start_str, end_str = line.split('-')
            start_ip = ipaddress.ip_address(start_str.strip())
            end_ip = ipaddress.ip_address(end_str.strip())
            if int(end_ip) < int(start_ip):
                raise ValueError("End IP is less than start IP")
            for ip_int in range(int(start_ip), int(end_ip) + 1):
                ips.append(str(ipaddress.ip_address(ip_int)))
            return ips
        except ValueError:
            pass

    # If none of the above parsing succeeded, return an empty list.
    return ips

def is_port_open(ip, port, timeout=1.0):
    """
    Check if the specified port is open on the given IP address.
    Returns True if the connection is successful, otherwise False.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def main():
    input_path = os.path.join("ip", "input.txt")
    list_path = os.path.join("ip", "list.txt")
    open_path = os.path.join("ip", "open.txt")

    all_ips = set()  # Use a set to avoid duplicate IP addresses

    # Read the input file and expand IP ranges or CIDRs.
    try:
        with open(input_path, "r") as infile:
            for line in infile:
                line = line.strip()
                if not line:
                    continue
                expanded = expand_ip_range(line)
                if not expanded:
                    print(f"Skipping invalid range or IP: {line}")
                else:
                    all_ips.update(expanded)
    except FileNotFoundError:
        print(f"Input file not found: {input_path}")
        return

    # Write all expanded IPs to list.txt
    try:
        with open(list_path, "w") as listfile:
            for ip in sorted(all_ips, key=lambda x: tuple(map(int, x.split('.')))):
                listfile.write(ip + "\n")
    except Exception as e:
        print(f"Error writing to list file: {e}")
        return

    # Check each IP for open ports 80 and 443.
    open_ips = []
    for ip in all_ips:
        if is_port_open(ip, 80) and is_port_open(ip, 443):
            open_ips.append(ip)

    # Write the IPs with both ports open to open.txt.
    try:
        with open(open_path, "w") as openfile:
            for ip in sorted(open_ips, key=lambda x: tuple(map(int, x.split('.')))):
                openfile.write(ip + "\n")
    except Exception as e:
        print(f"Error writing to open file: {e}")
        return

if __name__ == "__main__":
    main()
