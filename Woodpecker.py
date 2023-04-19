#!/usr/bin/env python3
import nmap
import argparse
import csv
import socket
import sys
import dns.resolver
import logging
import ipaddress

"""
Logging Levels:
------------------------------------------------------------
DEBUG: Detailed info
INFO: Confirmation of things working correctly
WARNING: (Default level) Indication things are not so good
ERROR: More serious prob preventing app from running
CRITICAL: Serious error

"""

PeckerLog = logging.getLogger(__name__)
PeckerLog.setLevel(logging.DEBUG)
PeckerFMT = logging.Formatter('%(created)f:%(levelname)s:%(message)s')
PeckerStream = logging.StreamHandler()
PeckerStream.setFormatter(PeckerFMT)
PeckerLog.addHandler(PeckerStream)

class Device:
    def __init__(self, ip, hostname):
        self.ip = ip
        self.hostname = hostname
        self.open_ports = []

    def add_open_port(self, port):
        self.open_ports.append(port)

def check_ip(target):
    try:
        ip_address = ipaddress.ip_address(target)
        # If the variable contains a single IP address
        return [str(ip_address)]
    except ValueError:
        try:
            ip_network = ipaddress.ip_network(target, strict=False)
            # If the variable contains an IP network with subnet mask
            return [str(ip) for ip in ip_network.hosts()]
        except ValueError:
            raise ValueError("Invalid IP address or network")

def scan_ports(ip):
    print(ip)
    try:
        Pecker = nmap.PortScanner()
    except nmap.PortScannerError:
        print('Nmap not found', sys.exc_info()[0])
        sys.exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)
    Pecker.scan(ip, arguments='-sS')
    return Pecker[ip]['tcp'].keys()

def scan_os(ip):
    try:
        Pecker = nmap.PortScanner()
    except nmap.PortScannerError:
        print('Nmap not found', sys.exc_info()[0])
        sys.exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)
    Pecker.scan(ip, arguments='-O')
    return Pecker[ip]['osmatch'][0]['name']

def resolve_hostname(ip, dns_server):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_server] 
    return resolver.query(ip, "PTR")[0].to_text()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def main():
    PeckerLog.info('Erecting the Pecker Network Scanner.')
    local_ip = get_local_ip()
    print(local_ip)
    PeckerParser = argparse.ArgumentParser(description='Pecker - Network Scanner')
    PeckerParser.add_argument('target', type=str, help='IP address(es) to scan. (10.0.0.1 OR 10.0.0.0/24)', default=local_ip)
    PeckerParser.add_argument('ports', type=str, help='Ports to scan (22 or 1-1024, etc.)')
    PeckerParser.add_argument('dns', type=str, help='DNS Server to use for name resolution. Default = 8.8.8.8', default='8.8.8.8')
    PeckerParser.add_argument('output', type=str, help='Output filename. Default = scan.csv', default='scan.csv')
    PeckerArgs = PeckerParser.parse_args()
    if PeckerArgs.target == local_ip:
        PeckerLog.info('Scanning the local ip address: ')
        PeckerLog.info(local_ip)
    else:
        PeckerLog.info('Scanning ip address(es): ')
        PeckerLog.info(PeckerArgs.ips)
    results = []
    for ip in check_ip(PeckerArgs.target):
        open_ports = scan_ports(ip)
        os_identification = scan_os(ip)
        dns_server = PeckerArgs.dns
        hostname = resolve_hostname(ip, dns_server)
        result = {'IP': ip, 'Open Ports': open_ports, 'OS Identification': os_identification, 'Hostname': hostname}
        results.append(result)
    with open(PeckerArgs.output, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['IP', 'Open Ports', 'OS Identification', 'Hostname'], delimiter='\t')
        writer.writeheader()
        for result in results:
            writer.writerow(result)

if __name__ == "__main__":
    main()
