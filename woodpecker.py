#!/usr/bin/env python3

import sys
import logging
import resources
import argparse
import dns.resolver
import csv
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
    devicelist = []
    csvheaders = config('CSVHEADERS', cast=Csv())

woodpeckerlog = logging.getLogger(__name__)
logging.basicConfig(filename='woodpecker.log', level = logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%y %I:%M:%S%p')

def main():
    woodpeckerlog.info("Woodpecker started")
    resources.wpgraphics.show_title(globals.version)
    print("Scan details:")
    print("-------------")
    if not resources.wplib.systemcheck(globals.logpath, globals.respath):
        sys.exit(1)
    else:
        print("Scanning target(s):", globals.targets)
        print("Scanning ports:", globals.ports)
        print("Resolving from DNS:", globals.dns)
        print("Output filename:", globals.output)
        print("")
        print("\033[32mScanner started...\033[0m                                                                         ", resources.wplib.get_time())
        resources.wpgraphics.drawdiv()
        for target in globals.targets:
            my_dict = {}
            print("Scanning:", target)
            resources.wpgraphics.progressbar(0, globals.scans)
            if resources.wplib.ping(target):
                #my_device = resources.device()
                my_dict['IP Address'] = target
                #my_device.add_ip(target)
                i = 1
                resources.wpgraphics.progressbar(i, globals.scans)
                my_dict['MAC Address'] = resources.wplib.get_mac(target)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                my_dict['Open TCP Ports'] = resources.wplib.scan_tcpports(target)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                my_dict['Open UDP Ports'] = resources.wplib.scan_udpports(target)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                if "80" in my_dict['Open TCP Ports']:
                    l4jresults = resources.wplib.check_log4j(target)
                    my_dict['Log4J Present'] = l4jresults[0]
                    my_dict['Log4J Vulnerable'] = l4jresults[1]
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                my_dict['OS Info'] = resources.wplib.scan_os(target)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
                my_dict['Hostname'] = resources.wplib.get_hostname(target)
                i += 1
                resources.wpgraphics.progressbar(i, globals.scans)
            else:
                resources.wpgraphics.progressbar(7, globals.scans)
                print("Host:", target, "does not respond.")
                #my_device = resources.device()
                my_dict['IP Address'] = target
                my_dict['Hostname'] = "Not Responding"
            globals.devicelist.append(my_dict)
        with open(globals.output, 'w', newline='') as file:
            #csvfile.write("IP Address,Hostname,OS Info,Open TCP Ports,Open UDP Ports,Log4J Present,Log4J Vulnerable\n")
            writer = csv.DictWriter(file, fieldnames=globals.csvheaders)
            writer.writeheader()
            for device in globals.devicelist:
                writer.writerow(device)
            #devlist = re
            #for device in devlist:
            #    print(resources.device.get_ip())
            #    device = resources.device.to_csv() 
            #    csvfile.write(device)

if __name__ == "__main__":
    main()