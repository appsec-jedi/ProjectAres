import nmap
import os


def scan_ports(host):
    scanner = nmap.PortScanner()
    scanner.scan(host, arguments='-sV -T4')
    open_ports = {}
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            open_ports[proto] = list(ports)
    return open_ports

# print(scan_ports('127.0.0.1'))