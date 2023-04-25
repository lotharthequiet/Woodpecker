#!/bin/python3

import sys
import nmap
import ipaddress
import subprocess
import socket
import re
import requests
from datetime import datetime

def get_time():
    try:
        now = datetime.now()
        time = now.strftime("%H:%M:%S")
        return time
    except:
        print("time not retrieved.")

def check_nmap():
    try:
        woodpecker = nmap.PortScanner()    
    except nmap.PortScannerError:
        print("Nmap not found", sys.exc_info()[0])
        sys.exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

def check_ip(address):
    try:
        ip_address = ipaddress.ip_address(address)
        # If the variable contains a single IP address
        return [str(ip_address)]
    except ValueError:
        try:
            ip_network = ipaddress.ip_network(address, strict=False)
            # If the variable contains an IP network with subnet mask
            return [str(ip) for ip in ip_network.hosts()]
        except ValueError:
            raise ValueError("Invalid IP address or network")

def ping(address):
    try:
        subprocess.check_output(["ping", "-c", "5", address])
        return True
    except subprocess.CalledProcessError:
        return False
    
def scan_tcpports(address):
    try:
        woodpecker = nmap.PortScanner()
        woodpecker.scan(address, arguments='-sS')
        return woodpecker[address]['tcp'].keys()
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

def scan_udpports(address):
    try:
        woodpecker = nmap.PortScanner()
        woodpecker.scan(address, arguments='-sU')
        return woodpecker[address]['udp'].keys()
    except:
        print("Unexpected error:", sys.exc_info()[0])
        
def scan_os(address):
    try:
        woodpecker = nmap.PortScanner()
        woodpecker.scan(address, arguments='-O')
        return woodpecker[address]['osmatch'][0]['name']
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

def get_hostname(address):
    try:
        hostname = socket.gethostbyaddr(address)[0]
        return hostname
    except socket.herror:
        return "Unable to resolve hostname."

def check_log4j(url):
    # Define a regular expression to match Log4J patterns in HTTP response body
    log4j_regex = r"(org\.apache\.log4j|log4j\.logger|log4j\.appender)"

    # Define a regular expression to extract the Log4J version number
    log4j_version_regex = r"log4j\.version\s*=\s*([0-9\.]+)"

    # Send an HTTP request to the URL and retrieve the response
    response = requests.get(url)

    # Search for Log4J patterns in the response body
    if re.search(log4j_regex, response.text):
        is_log4j_found = True
        # Extract the Log4J version number from the response body
        match = re.search(log4j_version_regex, response.text)
        if match:
            version_number = match.group(1)
            # Check if the Log4J version is vulnerable
            if version_number.startswith("1.2") or version_number.startswith("2.0") or version_number == "2.1":
                is_vulnerable = True
            else:
                is_vulnerable = False
        else:
            is_vulnerable = False
    else:
        is_log4j_found = False
        is_vulnerable = False
    return is_log4j_found, is_vulnerable