# Pecker
Pecker is a network scanner.


Dependencies: 

1) System must have NMAP installed

2) python-nmap


Python-nmap Docs: 
https://xael.org/pages/python-nmap-en.html






CURRENT ISSUES: 
------------------
DNS resolver doesn't work correctly.

TO DO: 
------
1. Get optional command line args that use the defaults if not specified.
2. Get the GetLocalIP func to return the CORRECT local ip address.
3. Output the data to the Device object. (Dump existing dict to object via FOR loop?)
4. Write the CSV doc from the devices objects instead of the current dictionary.
