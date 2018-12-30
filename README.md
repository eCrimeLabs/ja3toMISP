# ja3toMISP

Extracts JA3 fingerprints from a PCAP and adds them to an event in MISP as objects

Read more on eCrimeLabs Blog post:
https://www.ecrimelabs.com/blog/2018/12/30/ja3-to-misp-tool-released

This is a further development of https://github.com/salesforce/ja3/tree/master/python
"JA3 provides fingerprinting services on SSL packets. This is a python wrapper around JA3 logic in order to produce valid JA3 fingerprints from an input PCAP file."

However on top is added the integration into MISP for automatically creating the JA3 objects either to a new event or to an existing based on UUID.

When an PCAP file is parsed and the JA3 signatures are imported, ensure to add the description text for what type of signature it is related to.

Each Signature is created as a MISP object with the following Information:
- Ja3-fingerprint-md5
- IP source
- IP destination
- First-Seen

### Remember to create the file "keys.py":
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

misp_url = 'https://misp_instance'
misp_key = 'auth_key_value'
misp_verifycert = True
proxies = {
    'https://127.0.0.1:8090',
    'http://127.0.0.1:8090',
}

```

### Sample Usage:
```
~# python3 ja3toMISP.py -h


JA3 fingerprint to MISP Objects
(c)2018 eCrimeLabs
https://www.ecrimelabs.com
----------------------------------------

usage: ja3toMISP.py [-h] -f FILE [-a] [-j] [-c CREATE] [-u UUID] [-i]

Extracting JA3 fingerprints from PCAP files, and importing into MISP as
objects

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The pcap file to process
  -a, --any_port        Look for client hellos on any port instead of just 443
  -j, --json            Print out as JSON records for downstream parsing or
                        for debug reasons
  -c CREATE, --create CREATE
                        Create a new MISP event with the specified name
  -u UUID, --uuid UUID  Add to an allready existing event (input has to be
                        UUID)
  -i, --ids             Adds the to_ids to the source and destination IP's

```
