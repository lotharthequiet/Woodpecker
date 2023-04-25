#!/usr/bin/env python3

"""
Woodpecker Network Scanner version 0.1 Alpha
Written by: Lothar TheQuiet
Email: lotharthequiet@gmail.com
Github: https://github.com/lotharthequiet
"""

import time
import logging
import resources
import dns.resolver

dns_resolver = dns.resolver.Resolver()

woodpeckerlog = logging.getLogger(__name__)
woodpeckerlog.setLevel(logging.DEBUG)
fmt = logging.Formatter('%(levelname)s:%(message)s')
loghandler = logging.FileHandler('woodpecker.log')
loghandler.setFormatter(fmt)
woodpeckerlog.addHandler(loghandler)

VERSION = "0.1 Alpha"
TARGETS = ["10.10.80.3","10.10.80.25","10.10.80.35"]
PORTS = "1-1025"
DNS = dns_resolver.nameservers
OUTPUT = "scan.csv"

def main():
    woodpeckerlog.info("Woodpecker started")
    resources.wpgraphics.show_title(VERSION)
    resources.wplib.check_nmap()
    print("Scanning target(s):", TARGETS)
    print("Scanning ports:", PORTS)
    print("Resolving from DNS:", DNS)
    print("Output filename:", OUTPUT)
    for target in TARGETS:
        print("Scanning:", target)
        if resources.wplib.ping(target):
            my_device = resources.device()
            my_device.add_ip(target)
            for port in resources.wplib.scan_tcpports(target):
                my_device.add_tcpport(port)
            for port in resources.wplib.scan_udpports(target):
                my_device.add_udpport(port)
            if "80" in my_device.get_tcpports():
                l4jresults = resources.wplib.check_log4j(target)
                my_device.log4j = l4jresults[0]
            my_device.osinfo = resources.wplib.scan_os(target)
            my_device.hostname = resources.wplib.get_hostname(target)
            my_device.show_dev()
        else:
            print("Host:", target, "does not respond.")
            my_device = resources.device()
            my_device.add_ip(target)
            my_device.hostname = "Not Responding"
            my_device.show_dev()
    with open(OUTPUT, 'w') as csvfile:
        csvfile.write("IP Address,Hostname,OS Info,Open TCP Ports,Open UDP Ports,Log4J Present,Log4J Vulnerable\n")
        for device in resources.device.devices:
            row = resources.device.to_csv()
            csvfile.write(row)

if __name__ == "__main__":
    main()