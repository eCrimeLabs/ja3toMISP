#!/usr/bin/env python3
"""Generate JA3 fingerprints from PCAPs using Python3.
   and then either add to an existing event or create
   new event with the information from the PCAP's

   The calculation of the JA3 fingerprint is originally from:
   https://github.com/salesforce/ja3/blob/master/python/ja3/ja3.py

    MIT License

    Copyright (c) 2019 Dennis Rand (https://www.ecrimelabs.com)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""

import argparse
import dpkt
import json
import socket
import struct
import sys
import pprint
from datetime import datetime
from hashlib import md5
from pymisp import MISPObject
from pymisp import PyMISP
from pymisp import MISPEvent
from keys import misp_url, misp_key, misp_verifycert

__author__ = "Dennis Rand - eCrimeLabs"
__copyright__ = "Copyright (c) 2019, eCrimeLabs"
__credits__ = ["Tommy Stallings", "John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
__version__ = "1.0.0"
__maintainer__ = "Dennis Rand"


GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
SSL_PORT = 443
TLS_HANDSHAKE = 22

def splash():
    print ("\r\n")
    print ('JA3 fingerprint to MISP Objects')
    print ('(c)2018 eCrimeLabs')
    print ('https://www.ecrimelabs.com')
    print ("----------------------------------------\r\n")

def init(misp_url, misp_key):
    return PyMISP(misp_url, misp_key, misp_verifycert, 'json', debug=False)

def create_misp_objects(ja3_objects, misp_event, pcap_filename, misp, to_ids):
    #create_misp_objects(ja3_object, misp_event, pcap_filename)
    event = MISPEvent()
    event.from_dict(**misp_event)

    # is_in_misp_event(misp_event, ja3_checksum)
    print ("- Creating object(s)")
#    pprint.pprint(ja3_object)
    for ja3_object in ja3_objects:
        ja3_digest = (ja3_objects[ja3_object]['ja3_digest'])
        destination_ip = (ja3_objects[ja3_object]['destination_ip'])
        source_ip = (ja3_objects[ja3_object]['source_ip'])
        timestamp = (ja3_objects[ja3_object]['time'])

        if not ( is_in_misp_event(misp_event, ja3_digest, destination_ip) ):
            print ("\t " + ja3_digest + " -> " + destination_ip + " -> " + source_ip)
            misp_object = event.add_object(name='ja3', comment=pcap_filename, distribution=5, standalone=False)
            obj_attr = misp_object.add_attribute('ja3-fingerprint-md5', value=ja3_digest, distribution=5)
            misp_object.add_attribute('ip-src', value=source_ip, to_ids=to_ids, distribution=5)
            misp_object.add_attribute('ip-dst', value=destination_ip, to_ids=to_ids, distribution=5)
            misp_object.add_attribute('first-seen', value=timestamp, disable_correlation=True, distribution=5)

    try:
        misp.update(event)
    except (KeyError, RuntimeError, TypeError, NameError):
        print ("An error occoured when updating the event")
        sys.exit()

    print ("- The MISP objects seems to have been added correctly to the event.... \r\n\r\n")

def is_in_misp_event(misp_event, ja3_digest, destination_ip):
    found = False
    for obj_loop in misp_event['Object']:
        found_ja3 = False
        found_ip = False
        for attr_loop in obj_loop['Attribute']:
            if(attr_loop['value'] == ja3_digest):
                found_ja3 = True
            elif(attr_loop['value'] == destination_ip):
                found_ip = True
        if( (found_ja3) and found_ip ):
            found = True
    return(found)

def convert_ip(value):
    """Convert an IP address from binary to text.
    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.
    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]

    return data, size + byte_len


def ntoh(buf):
    """Convert to network order.
    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.
    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.
    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results


def process_pcap(pcap, any_port=False):
    """Process packets within the PCAP.
    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """

    results = dict() # list()
    for timestamp, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            continue

        if not isinstance(eth.data, dpkt.ip.IP):
            # We want an IP packet
            continue
        if not isinstance(eth.data.data, dpkt.tcp.TCP):
            # TCP only
            continue

        ip = eth.data
        tcp = ip.data

        if not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT or any_port):
            # Doesn't match SSL port or we are picky
            continue
        if len(tcp.data) <= 0:
            continue

        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        records = list()

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
            continue

        if len(records) <= 0:
            continue

        for record in records:
            if record.type != TLS_HANDSHAKE:
                continue
            if len(record.data) == 0:
                continue
            client_hello = bytearray(record.data)
            if client_hello[0] != 1:
                # We only want client HELLO
                continue
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                continue
            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                # Still not the HELLO
                continue

            client_handshake = handshake.data
            buf, ptr = parse_variable_array(client_handshake.data, 1)
            buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
            ja3 = [str(client_handshake.version)]

            # Cipher Suites (16 bit values)
            ja3.append(convert_to_ja3_segment(buf, 2))
            ja3 += process_extensions(client_handshake)
            ja3 = ",".join(ja3)
            ja3_digest = md5(ja3.encode()).hexdigest()

            data = dict()

            data = {"source_ip": convert_ip(ip.src),
                      "destination_ip": convert_ip(ip.dst),
                      "source_port": tcp.sport,
                      "destination_port": tcp.dport,
                      "ja3": ja3,
                      "ja3_digest": ja3_digest,
                      "timestamp": timestamp,
                      "time": datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%SZ')}

            results[ja3_digest + '-' + convert_ip(ip.dst)] = data

    return results


def main():
    splash()
    """Intake arguments from the user and print out JA3 output."""
    desc = "Extracting JA3 fingerprints from PCAP files, and importing into MISP as objects"
    parser = argparse.ArgumentParser(description=(desc))
    parser.add_argument("-f", "--file", required=True, help="The pcap file to process")
    parser.add_argument("-a", "--any_port", required=False,
                        action="store_true", default=False,
                        help="Look for client hellos on any port instead of just 443")
    parser.add_argument("-j", "--json", required=False, action="store_true",
                        help="Print out as JSON records for downstream parsing or for debug reasons")
    parser.add_argument("-c", "--create", required=False, type=str,
                        help="Create a new MISP event with the specified name")
    parser.add_argument("-u", "--uuid", required=False, type=str,
                        help="Add to an allready existing event (input has to be UUID)")
    parser.add_argument("-i", "--ids", required=False, action="store_true", default=False,
                        help="Adds the to_ids to the source and destination IP's")
    args = parser.parse_args()

    # Use an iterator to process each line of the file
    ja3_objects = None
    pcap_filename = args.file
    to_ids = args.ids
    with open(args.file, 'rb') as fp:
        try:
            capture = dpkt.pcap.Reader(fp)
        except ValueError as e:
            raise Exception("File doesn't appear to be a PCAP: %s" % e)
        ja3_objects = process_pcap(capture, any_port=args.any_port)

    if (args.json):
        ja3_objects = json.dumps(ja3_objects, indent=4, sort_keys=True)
        print(ja3_objects)
    elif (args.uuid):
        # Add to existing UUID
        try:
            misp = init(misp_url, misp_key)
            misp_event = misp.get_event(args.uuid)['Event']
        except KeyError as e:
            print ("An error occoured getting the UUID, either connection issues or UUID does not exits.")
            sys.exit(0)
        create_misp_objects(ja3_objects, misp_event, pcap_filename, misp, to_ids)
    elif (args.create):
        # Create a new event in MISP
        pass
    else:
        pass
        

if __name__ == "__main__":
        main()
