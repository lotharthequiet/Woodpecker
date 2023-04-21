#!/usr/bin/env python3
import argparse
import csv
import logging
import json
import wplib

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
fmt = logging.Formatter('%(levelname)s:%(message)s')
loghandler = logging.FileHandler('woodpecker.log')
loghandler.setFormatter(fmt)
woodpeckerlog.addHandler(loghandler)

VERSION = "0.1 Alpha"
TARGETS = ["150.199.1.9","150.199.1.10","150.199.1.11"]
PORTS = "1-1025"
DNS = "8.8.8.8"
OUTPUT = "scan.csv"

class Device:
    devices = []

    def __init__(self):
        self.ip = ""
        self.hostname = ""
        self.openports = []
        self.osinfo = ""
        Device.devices.append(self)

    def get_ip(self):
        return self.ip
    
    def add_ip(self, ip):
        self.ip = ip

    def get_hostname(self):
        return self.hostname
    
    def add_hostname(self, hostname):
        self.hostname = hostname

    def get_openports(self):
        return self.openports
    
    def add_openport(self, port):
        self.openports.append(port)

    def get_osinfo(self):
        return self.osinfo
    
    def add_osinfo(self, osinfo):
        self.osinfo = osinfo

    def show_dev(self):
        print("IP:", self.ip, "Hostname:", self.hostname, "OS:", self.osinfo, "Open Ports:", self.openports)

    def show_alldevs(self):
        for device in Device.devices:
            device.show_dev()

def main():
    wplib.show_title(VERSION)
    wplib.check_nmap()
    print("Scanning target(s):", TARGETS)
    print("Scanning ports:", PORTS)
    print("Resolving from DNS:", DNS)
    print("Output filename:", OUTPUT)
    for target in TARGETS:
        print("Scanning:", target)
        if wplib.ping(target):
            my_device = Device()
            my_device.add_ip(target)
            for port in wplib.scan_ports(target):
                my_device.add_openport(port)
            my_device.osinfo = wplib.scan_os(target)
            my_device.hostname = wplib.get_hostname(target)
            my_device.show_dev()
        else:
            print("Host:", target, "does not respond.")
            my_device = Device()
            my_device.add_ip(target)
            my_device.hostname = "Not Responding"
            my_device.show_dev()
    #Device.show_alldevs()

if __name__ == "__main__":
    main()