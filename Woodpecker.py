#!/usr/bin/env python3

import time
import logging
import resources
import dns.resolver
from decouple import config
from decouple import Csv

__author__ = "Lothar TheQuiet"
__email__ = "lotharthequiet@gmail.com"
__version__ = "0.1"
__status__ = "Alpha"

dns_resolver = dns.resolver.Resolver()

woodpeckerlog = logging.getLogger(__name__)
woodpeckerlog.setLevel(logging.DEBUG)
fmt = logging.Formatter('%(levelname)s:%(message)s')
loghandler = logging.FileHandler('woodpecker.log')
loghandler.setFormatter(fmt)
woodpeckerlog.addHandler(loghandler)

class globals:
    version = config('VERSION')
    targets = config('TARGETS', cast=Csv())
    #targets = ["10.0.0.31"]
    ports = config('PORTS')
    dns = dns_resolver.nameservers
    if config('OUTPUT') is not None:
        output = "scan.csv"
    else:
        output = config('output')
    scans = config('SCANS')

def main():
    woodpeckerlog.info("Woodpecker started")
    resources.wpgraphics.show_title(globals.version)
    resources.wplib.check_nmap()
    print("Scanning target(s):", globals.targets)
    print("Scanning ports:", globals.ports)
    print("Resolving from DNS:", globals.dns)
    print("Output filename:", globals.output)
    for target in globals.targets:
        print("Scanning:", target)
        resources.wpgraphics.progressbar(0, globals.scans)
        if resources.wplib.ping(target):
            my_device = resources.device()
            my_device.add_ip(target)
            i = 1
            resources.wpgraphics.progressbar(i+1, globals.scans)
            for port in resources.wplib.scan_tcpports(target):
                my_device.add_tcpport(port)
            resources.wpgraphics.progressbar(i+1, globals.scans)
            for port in resources.wplib.scan_udpports(target):
                my_device.add_udpport(port)
            resources.wpgraphics.progressbar(i+1, globals.scans)
            if "80" in my_device.get_tcpports():
                l4jresults = resources.wplib.check_log4j(target)
                my_device.log4j = l4jresults[0]
            resources.wpgraphics.progressbar(i+1, globals.scans)
            my_device.osinfo = resources.wplib.scan_os(target)
            resources.wpgraphics.progressbar(i+1, globals.scans)
            my_device.hostname = resources.wplib.get_hostname(target)
            resources.wpgraphics.progressbar(i+1, globals.scans)
            my_device.show_dev()
        else:
            print("Host:", target, "does not respond.")
            my_device = resources.device()
            my_device.add_ip(target)
            my_device.hostname = "Not Responding"
            my_device.show_dev()
    with open(globals.output, 'w') as csvfile:
        csvfile.write("IP Address,Hostname,OS Info,Open TCP Ports,Open UDP Ports,Log4J Present,Log4J Vulnerable\n")
        for dev in resources.device.devices:
            device = resources.device.to_csv() 
            csvfile.write(device)

if __name__ == "__main__":
    main()