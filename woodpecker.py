#!/usr/bin/env python3

import sys
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

class globals:
    version = config('VERSION')
    targets = config('TARGETS', cast=Csv())
    ports = config('PORTS')
    dns = dns_resolver.nameservers
    if config('OUTPUT') is not None:
        output = "scan.csv"
    else:
        output = config('output')
    scans = config('SCANS')
    logtime = resources.wplib.get_time()
    logpath = config('LOGPATH')
    respath = config('RESPATH')

woodpeckerlog = logging.getLogger(__name__)
woodpeckerlog.setLevel(logging.DEBUG)
fmt = logging.Formatter('%(levelname)s,%(message)s')
loghandler = logging.FileHandler('woodpecker.log')
loghandler.setFormatter(fmt)
woodpeckerlog.addHandler(loghandler)

def main():
    woodpeckerlog.info("Woodpecker started")
    resources.wpgraphics.show_title(globals.version)
    if not resources.wplib.systemcheck(globals.logpath, globals.respath):
        sys.exit(1)
    else:
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
                resources.wpgraphics.progressbar(i, globals.scans)
                tcpports = resources.wplib.scan_tcpports(target)
                for port in tcpports:
                    my_device.add_tcpport(port)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                udpports = resources.wplib.scan_udpports(target)
                for port in udpports:
                    my_device.add_udpport(port)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                if "80" in tcpports:
                    l4jresults = resources.wplib.check_log4j(target)
                    my_device.log4j = l4jresults[0]
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                my_device.osinfo = resources.wplib.scan_os(target)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                my_device.hostname = resources.wplib.get_hostname(target)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                my_device.show_dev()
            else:
                resources.wpgraphics.progressbar(6, globals.scans)
                print("Host:", target, "does not respond.")
                my_device = resources.device()
                my_device.add_ip(target)
                my_device.hostname = "Not Responding"
                my_device.show_dev()
        with open(globals.output, mode='w') as csvfile:
            csvfile.write("IP Address,Hostname,OS Info,Open TCP Ports,Open UDP Ports,Log4J Present,Log4J Vulnerable\n")
            devlist = re
            for device in devlist:
                print(resources.device.get_ip())
                device = resources.device.to_csv() 
                csvfile.write(device)

if __name__ == "__main__":
    main()