#!/bin/python3

import sys
import nmap
import ipaddress
import subprocess
import socket

def check_nmap():
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
    
def scan_ports(address):
    try:
        woodpecker = nmap.PortScanner()
        woodpecker.scan(address, arguments='-sS')
        return woodpecker[address]['tcp'].keys()
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)
    
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

def show_title(ver):
    print("\033[1;31m _       __                __", end="")
    print("\033[1;96m                __            ")
    print("\033[1;31m| |     / /___  ____  ____/ /", end="")
    print("\033[1;96m___  ___  _____/ /_____  _____")
    print("\033[1;31m| | /| / / __ \/ __ \/ __  /", end="")
    print("\033[1;96m __ \/ _ \/ ___/ //_/ _ \/ ___/")
    print("\033[1;31m| |/ |/ / /_/ / /_/ / /_/ /", end="")
    print("\033[1;96m /_/ /  __/ /__/ ,< /  __/ /    ")
    print("\033[1;31m|__/|__/\____/\____/\__,_/", end="")
    print("\033[1;96m .___/\___/\___/_/|_|\___/_/     ")
    print("\033[1;96m                        /_/                           \033[0;0m")
    print("    Network Scanner          Version:", ver)
    print("-----------------------------------------------------------")
    print("Written by: Lothar TheQuiet")
    print("lotharthequiet@gmail.com")
    print("")
    print("")