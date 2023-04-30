# Woodpecker
Woodpecker is a network scanner.


Dependencies: 

1) System must have NMAP installed

2) python-nmap


Python-nmap Docs: 
https://xael.org/pages/python-nmap-en.html






CURRENT ISSUES: 
------------------
- Cannot process list of lists in TARGET

TO DO: 
------
1. Get optional command line args that use the defaults if not specified.
2. Implement IP Helper.
3. Write the CSV doc from the devices objects.
4. Add module for fileshare detection.
5. Add module for printer share detection.
6. Add module for Log4J vuln assessment. 
7. Check for banners on open ports. (Telnet, FTP, SSH, SMTP)
8. Check for SMTP mail relay if port open.
9. CHeck for TLS version.
10. Check for SSH version.
11. Check for SNMP version.
12. Start reporting vulnerabilities such as open FTP ports, telnet, etc.
13. Add module for DNS enum
14. Follow the Pentester Cheat Sheets for more
15. Add time of scan
16. add progress bar

