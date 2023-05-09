#!/bin/python3

import os
import sys
import platform
import nmap
import ipaddress
import subprocess
import socket
import re
import requests
import portend
from datetime import datetime

def check_os():
    system = platform.system()
    if system == "Windows":
        hostosinfo = "Windows"
    elif system == "Linux":
        hostosinfo = "Linux"
    elif system == "Darwin":
        hostosinfo = "MacOS"
    else:
        hostosinfo = "Unknown OS"
    return hostosinfo

def systemcheck(logpath, respath):
    print("Host OS: ", end="")
    print(check_os())
    print("Checking system...", end="")
    if not os.path.exists(logpath) and not os.path.exists(respath):
        osinfo = False
        nmap = False
    else:
        osinfo = True
        nmap = check_nmap()
    if not osinfo and nmap:
        print("System check failed.")
        return False
    else:
        print("System check passed.")
        return True
        
def get_time():
    try:
        now = datetime.now()
        time = now.strftime("%I:%M:%S %p")
        return time
    except:
        print("time not retrieved.")

def check_nmap():
    try:
        woodpecker = nmap.PortScanner()    
    except nmap.PortScannerError:
        return False
    except:
        return False
    return True

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

def get_mac(address):
    try:
        output = subprocess.check_output(["arp", "-n", address]).decode("utf-8")
        mac = output.split()[3]
        return mac
    except subprocess.CalledProcessError:
        return "00:00:00:00:00:00"

def ping(address):
    with open(os.devnull, 'w') as null:
        try:
            subprocess.check_call(["ping", "-c", "5", address], stdout=null, stderr=null)
            return True
        except subprocess.CalledProcessError:
            return False
    
def scan_ports(address, sub):
    if sub == "tcp":
        try:
            woodpecker = nmap.PortScanner()
            woodpecker.scan(address, arguments='-sS')
            tcplist =  woodpecker[address]['tcp'].keys()
            tcpsrvlist = []
            for port in tcplist:
                try:
                    srv = socket.getservbyport(port, 'tcp')
                except OSError:
                    srv = "Unknown"
                tcpsrvlist.append(srv)
                nm = nmap.PortScanner()
                nm.scan(address, str(port), arguments='-sV')
                verlist = []
                try:
                    ver = nm[address]['tcp'][port]['version']
                    verlist.append(ver)
                except KeyError:
                    ver = "Not found."
                except ValueError:
                    ver = "Not found."
            tcpports = dict(zip(tcplist, tcpsrvlist, ver))
            return tcpports
        except:
            print("Unexpected error:", sys.exc_info()[0])
            sys.exit(1)
    elif sub == "udp":
        try:
            woodpecker = nmap.PortScanner()
            woodpecker.scan(address, arguments='-sU')
            udplist = woodpecker[address]['udp'].keys()
            udpsrvlist = []
            for port in udplist:
                try:
                    srv = socket.getservbyport(port, 'udp')
                except OSError:
                    srv = "Unknown"
                udpsrvlist.append(srv)
                #nm = nmap.PortScanner()
                #nm.scan(address, str(port), arguments='-sV')
                #verlist = []
                #try:
                #    ver = nm[address]['udp'][port]['version']
                #    verlist.append(ver)
                #except KeyError:
                #    ver = "Not found."
                #except ValueError:
                #    ver = "Not found."
            udpports = dict(zip(udplist, udpsrvlist))
            return udpports
        except:
            print("Unexpected error:", sys.exc_info()[0])
    else:
        print("Subprotocol error.")
        
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