import netifaces
import ipaddress
import subprocess
import nmap
import socket

from concurrent.futures import ThreadPoolExecutor, as_completed
from ipwhois import IPWhois

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(f"Error: Unable to resolve domain '{domain}'")
        return None

def get_external_network_range(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()  # Lookup RDAP information for the IP.
        # The network range may be available under the 'network' key with its 'cidr' entry.
        network_range = results.get('network', {}).get('cidr')
        return network_range
    except Exception as e:
        print(f"Error retrieving network range for {ip}: {e}")
        return None

def get_local_network_info(selected_interface):
    addrs = netifaces.ifaddresses('en0')
    ip_info = addrs[netifaces.AF_INET]
    if not ip_info:
        print(f"Error: No IPv4 address found for interface {selected_interface}")
        return None

    ip_addr = ip_info[0]['addr']
    netmask = ip_info[0]['netmask']

    network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
    return selected_interface, ip_addr, netmask, str(network)

def ping_host(ip):
    p = subprocess.Popen(
        ["ping", "-c", "1", str(ip)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )
    p.wait()
    return ip if p.poll() == 0 else None

def iterate_network(network_range):
    hosts = []
    try:
        network = ipaddress.ip_network(network_range, strict=False)
        total_ips = network.num_addresses
        progress_threshold = 5
        next_progress = progress_threshold
        scanned = 0

        print("Iterating through the network to identify active hosts")

        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in network}

            for future in as_completed(future_to_ip):
                scanned += 1
                current_percent = scanned / total_ips * 100
                if current_percent >= next_progress:
                    print("+", end="", flush=True)
                    next_progress += progress_threshold

                result = future.result()
                if result is not None:
                    hosts.append(result)

        print("\nHosts online:")
        for host in hosts:
            print(host)
        return hosts
    except ValueError as e:
        print(f"Error: {e}") 

def scan_host(host):
    scanner = nmap.PortScanner()
    
    scanner.scan(host, arguments='-sT -sV -T4 --osscan-limit')
    
    if host in scanner.all_hosts():
        host_info = scanner[host]
        print(f"Host: {host} ({host_info.hostname()})")
        print(f"State: {host_info.state()}")
        
        for proto in host_info.all_protocols():
            print(f"Protocol: {proto}")
            ports = sorted(host_info[proto].keys())
            for port in ports:
                port_data = host_info[proto][port]
                print(f"  Port {port}: {port_data['state']} (Service: {port_data.get('name', 'unknown')})")
    else:
        print(f"No scan results for {host}")

def scan_network(ips):
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_host = {executor.submit(scan_host, str(ip)): ip for ip in ips}
        for future in as_completed(future_to_host):
            try:
                future.result()
            except Exception as e:
                print(f"Error scanning {future_to_host[future]}: {e}")

def make_selection():
    print("What type of network are you exploring?")
    print("1. Local")
    print("2. External")
    local_or_external = input("Make selection: ")
    if local_or_external == "1":
        af_inet = netifaces.AF_LINK
        all_interfaces = netifaces.interfaces()
        print("Available interfaces:")
        for inf in all_interfaces:
            if inf.startswith('en'):
                addrs = netifaces.ifaddresses(inf)
                print(inf)

        interface_input = input("Which interface would you like to use? (Default en0): ")

        if interface_input == "":
            selected_interface = "en0"
        elif interface_input in all_interfaces:
            selected_interface = interface_input
        else:
            print("Invalid interface selected")

        result = get_local_network_info(selected_interface)

        if result:
            interface, ip_addr, netmask, network_range = result
            print(f"Interface:     {interface}")
            print(f"IP Address:    {ip_addr}")
            print(f"Netmask:       {netmask}")
            print(f"Network Range: {network_range}")

    elif local_or_external == "2":
        external_input = input("What is the ip or domain you want to investigate? ").strip()
        external_cidr = get_external_network_range(external_input)
        if any(c.isalpha() for c in external_input):
            resolved_ip = resolve_domain(external_input)
            if resolved_ip is not None:
                print(f"Resolved {external_input} to {resolved_ip}")
                external_ip = resolved_ip
            else:
                exit(1)
        else:
            external_ip = external_input

        # Now use the IP for further investigation.
        network_range = get_external_network_range(external_ip)
        print(f"IP Address:    {external_ip}")
        print(f"Network Range: {network_range}")
        # Optionally, proceed with scanning the network or the single host.
    else:
        print("There's only two options here")
        make_selection()
    
    selection = input("Would you like to further investigate the network? (yes/no): ")
    if selection.lower() == "yes":
        online_hosts = iterate_network(network_range)
        scan_network(online_hosts)
    else:
        print("Later tater!")
