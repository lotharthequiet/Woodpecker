# Pecker
Pecker is a network scanner.


Dependencies: 

1) System must have NMAP installed

2) python-nmap


Python-nmap Docs: 
https://xael.org/pages/python-nmap-en.html






CURRENT ISSUES: 
------------------
Traceback (most recent call last):
  File "/Users/lothar/Desktop/Lothar/Py Scripts/Pecker.py", line 97, in <module>
    main()
  File "/Users/lothar/Desktop/Lothar/Py Scripts/Pecker.py", line 83, in main
    open_ports = scan_ports(ip)
  File "/Users/lothar/Desktop/Lothar/Py Scripts/Pecker.py", line 30, in scan_ports
    return Pecker[ip]['tcp'].keys()
  File "/Users/lothar/Library/Python/3.8/lib/python/site-packages/nmap/nmap.py", line 600, in __getitem__
    return self._scan_result["scan"][host]
KeyError: '1'



TO DO: 
------
1. Get optional command line args that use the defaults if not specified.
2. Get the GetLocalIP func to return the CORRECT local ip address.
3. Output the data to the Device object. (Dump existing dict to object via FOR loop?)
4. Write the CSV doc from the devices objects instead of the current dictionary.
