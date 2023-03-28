#!/usr/bin/env python3

import socket
import csv
import sys
import nmap

class Device:
    def __init__(self, ip, hostname):
        self.ip = ip
        self.hostname = hostname
        self.open_ports = []

    def add_open_port(self, port):
        self.open_ports.append(port)

# Create a new nmap scanner
try:   
    Pecker = nmap.PortScanner()
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(1)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(1)

#OsDetector = nmap.PortScanner()

def main():
    # Define the target host IP address and ports to be scanned
    if len(sys.argv) != 3:
        print("Usage: Pecker.py network_address/subnet_mask ports")
        return
    target = sys.argv[1]
    ports = sys.argv[2]

    # Define the port scanner
    Pecker.scan(target, ports, arguments='-O -sT -sU -sV')

    # Define the OS scanner
    #OsDetector.scan(target, arguments='-O')
    print('This network has been fondled by Pecker.')
    for host in Pecker.all_hosts():
        print('Host: %s (%s)' % (host, Pecker[host].hostname()))
        print('State: %s' % Pecker[host].state())

        if 'osmatch' in Pecker[host]:
            for osmatch in Pecker[host]['osmatch']:
                print('OsMatch.name : {0}'.format(osmatch['name']))
                print('OsMatch.accuracy : {0}'.format(osmatch['accuracy']))
                print('OsMatch.line : {0}'.format(osmatch['line']))
                print('')

                if 'osclass' in osmatch:
                    for osclass in osmatch['osclass']:
                        print('OsClass.type : {0}'.format(osclass['type']))
                        print('OsClass.vendor : {0}'.format(osclass['vendor']))
                        print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
                        print('OsClass.osgen : {0}'.format(osclass['osgen']))
                        print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
                        print('')

    for proto in Pecker[host].all_protocols():
        print('----------')
        print('Protocol: %s' % proto)

        lport = Pecker[host][proto].keys()
        for port in lport:
            print('port: %s\tstate : %s' % (port, Pecker[host][proto][port]['state']))
        #print('OS: %s' % OsDetector[host]['osmatch'][0]['osclass'][0]['osfamily'])
    print(Pecker.csv())
    #print(OsDetector.csv())

if __name__ == "__main__":
    main()
