#!/usr/bin/env python3
"""Check controlled test markers on TUN and their absence from outer UDP."""
import argparse
import json
from pathlib import Path
import struct
import sys

MARKER = b'BPROTO_LAB_PROBE'


def analyze(path, interfaces):
    counts = dict(wire_udp=0, tun_marker_packets=0, tun_http_requests=0, tun_http_responses=0, cleartext_wire_markers=0)
    with path.open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24: raise ValueError('Truncated PCAP header')
        endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>', b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}.get(header[:4])
        if endian is None: raise ValueError('Unsupported capture format; use tcpdump classic PCAP')
        link = struct.unpack(endian+'I', header[20:24])[0] & 0xffff
        if link not in (113, 276): raise ValueError('Expected Linux any-interface capture (SLL or SLL2)')
        if link == 113: raise ValueError('SLL v1 lacks interface indices; use a tcpdump version with SLL2 support')
        while True:
            record = stream.read(16)
            if not record: break
            if len(record) != 16: raise ValueError('Truncated packet record')
            length = struct.unpack(endian+'IIII', record)[2]
            if length > 1048576: raise ValueError('Excessive captured packet size')
            packet = stream.read(length)
            if len(packet) != length: raise ValueError('Truncated packet data')
            if len(packet) < 40: continue
            protocol = struct.unpack('!H', packet[:2])[0]
            index = struct.unpack('!I', packet[4:8])[0]
            name = interfaces.get(str(index), '')
            if protocol != 0x0800: continue
            ip = packet[20:]
            ihl = (ip[0] & 15) * 4
            if ip[0] >> 4 != 4 or ihl < 20 or len(ip) < ihl: continue
            if ip[9] == 17 and len(ip) >= ihl+8:
                source, target = struct.unpack('!HH', ip[ihl:ihl+4])
                if 4443 in (source, target) and name != 'bplab0':
                    counts['wire_udp'] += 1
                    if MARKER in ip[ihl+8:]: counts['cleartext_wire_markers'] += 1
            if name == 'bplab0':
                if MARKER in ip[ihl:]: counts['tun_marker_packets'] += 1
                if ip[9] == 6:
                    if b'GET /probe ' in ip[ihl:]: counts['tun_http_requests'] += 1
                    if b'synthetic test response' in ip[ihl:]: counts['tun_http_responses'] += 1
    if not counts['wire_udp']: raise ValueError('No outer UDP traffic captured')
    if counts['cleartext_wire_markers']: raise ValueError('Controlled plaintext marker leaked into outer UDP')
    if not counts['tun_marker_packets'] or not counts['tun_http_requests'] or not counts['tun_http_responses']:
        raise ValueError('Capture does not prove controlled HTTP request and response through TUN: ' + json.dumps(counts))
    return dict(result='passed', **counts, limit='Marker absence is a regression check, not an independent cryptographic audit; Internet forwarding and Android were not tested')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', type=Path)
    parser.add_argument('interfaces', type=Path)
    args = parser.parse_args()
    try: print(json.dumps(analyze(args.pcap, json.loads(args.interfaces.read_text())), indent=2))
    except (OSError, ValueError) as error: print(str(error), file=sys.stderr); sys.exit(1)
