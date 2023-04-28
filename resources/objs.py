#!/bin/python3

class device:
    devices = []

    def __init__(self):
        self.ip = ""
        self.hostname = ""
        self.tcpports = []
        self.udpports = []
        self.osinfo = ""
        self.log4j = False
        self.log4j_vuln = False
        #self.openshares = False
        #self.shareprotocol = ""
        #self.shares = []
        #device.devices.append(self)

    def get_ip(self):
        return self.ip
    
    def add_ip(self, ip):
        self.ip = ip

    def get_hostname(self):
        return self.hostname
    
    def add_hostname(self, hostname):
        self.hostname = hostname

    def get_tcpports(self):
        return self.tcpports
    
    def add_tcpport(self, port):
        self.tcpports.append(port)

    def get_udpports(self):
        return self.udpports
    
    def add_udpport(self, port):
        self.udpports.append(port)

    def get_osinfo(self):
        return self.osinfo
    
    def add_osinfo(self, osinfo):
        self.osinfo = osinfo

    def get_log4j(self):
        return self.log4j
    
    def setlog4j(self, data):
        self.log4j = data

    def get_log4jvuln(self):
        return self.log4j_vuln
    
    def set_log4jvuln(self, data):
        self.log4j_vuln = data

    def show_dev(self):
        string = "IP:", self.ip, "Hostname:", self.hostname, "OS:", self.osinfo, "Open TCP Ports:", self.tcpports, "Open UDP Ports:", self.udpports, "Log4J Present:", self.log4j, "Log4J Vulnerable:", self.log4j_vuln
        return string

    def to_csv(self):
        csv_string = f"{self.ip},{self.hostname},{self.osinfo},{','.join(map(str, self.tcpports))},{','.join(map(str, self.udpports))},{int(self.log4j)},{int(self.log4j_vuln)}\n"
        return csv_string
    
class log:
    def __init__(self, time, level, message):
        self.time = time
        self.level = level
        self.message = message

    def set_time(self, time):
        self.time = time

    def set_level(self, level):
        self.level = level

    def set_message(self, message):
        self.message = message

    def show_log(self):
        print(self.time,":",self.level,":",self.message)
