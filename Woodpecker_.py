#!/usr/bin/env python3
import nmap
import argparse
import csv
import socket
import sys
import dns.resolver
import logging
import ipaddress
import json

"""
Logging Levels:
------------------------------------------------------------
DEBUG: Detailed info
INFO: Confirmation of things working correctly
WARNING: (Default level) Indication things are not so good
ERROR: More serious prob preventing app from running
CRITICAL: Serious error

"""

woodpeckerlog = logging.getLogger(__name__)
woodpeckerlog.setLevel(logging.DEBUG)
fmt = logging.Formatter('%(created)f:%(levelname)s:%(message)s')
stream = logging.StreamHandler()
stream.setFormatter(fmt)
woodpeckerlog.addHandler(stream)

TARGET = "10.0.0.31"
PORTS = "1-1025"
DNS = ""
OUTPUT = "scan.csv"

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
        woodpecker = nmap.PortScanner()
        woodpecker.scan(ip, arguments='-sS')
        return woodpecker[ip]['tcp'].keys()
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)
    
def scan_os(ip):
    try:
        woodpecker = nmap.PortScanner()
        woodpecker.scan(ip, arguments='-O')
        return woodpecker[ip]['osmatch'][0]['name']
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

def main():
    try:
        print("Checking for NMAP...")
        woodpecker = nmap.PortScanner()
        print("Nmap found.")
    except nmap.PortScannerError:
        print("Nmap not found", sys.exc_info()[0])
        sys.exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

if __name__ == "__main__":
    main()
