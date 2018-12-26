# ja3toMISP

Extracts JA3 fingerprints from a PCAP and adds them to an event in MISP as objects

This is a fork of https://github.com/salesforce/ja3/tree/master/python
"JA3 provides fingerprinting services on SSL packets. This is a python wrapper around JA3 logic in order to produce valid JA3 fingerprints from an input PCAP file."

However on top is added the integration into MISP for automatically creating the JA3 objects either to a new event ot to an existing based on UUID.

Remember to create the file "keys.py":
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

misp_url = 'https://misp_instance/'
misp_key = '' # The MISP auth key can be found on the MISP web interface under the automation section
misp_verifycert = True

```

Sample Usage:
```
~# python3 vt2misp.py -u 5b53275a-003c-4dcc-b4ce-710f9f590eb0 -a "USBGuard" --force -c 7657fcb7d772448a6d8504e4b20168b8
Virustotal to MISP
(c)2018 eCrimeLabs
https://www.ecrimelabs.com
----------------------------------------
```
