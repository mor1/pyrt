#! /usr/bin/env python3

##     Copyright (C) 2020 Richard Mortier <mort@cantab.net>

##     This program is free software; you can redistribute it and/or
##     modify it under the terms of the GNU General Public License as
##     published by the Free Software Foundation; either version 2 of the
##     License, or (at your option) any later version.

##     This program is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##     General Public License for more details.

##     You should have received a copy of the GNU General Public License
##     along with this program; if not, write to the Free Software
##     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
##     02111-1307 USA

import pprint, json, argparse, sys
import mrtd, dpkt
from mutils import *

## dpkt.pcap.Reader iterator doesn't provide the PCAP header, only the timestamp
class R(dpkt.pcap.Reader):
    def __iter__(self):
        while 1:
            buf = self._Reader__f.read(dpkt.pcap.PktHdr.__hdr_len__)
            if not buf:
                break
            hdr = self._Reader__ph(buf)
            buf = self._Reader__f.read(hdr.caplen)
            yield (hdr.tv_sec + (hdr.tv_usec / self._divisor), hdr, buf)

from dpkt.compat import compat_ord
def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

class PcapNotIP(Exception):
    pass

def ip_getter(pcap):
    dlt = pcap.datalink()
    if dlt == dpkt.pcap.DLT_PPP:
        return lambda bs: dpkt.ppp.PPP(bs).data

    elif dlt == dpkt.pcap.DLT_LINUX_SLL:
        def f(bs):
            sll = dpkt.sll.SLL(bs)
            if sll.ethtype == 0x0800: ## IPv4
                return sll.ip
            elif sll.ethtype == 0x0806: ## ARP
                print("[dropped ARP / %d bytes]..." %
                      hdr.len, end="", sep="", file=sys.stderr)
                raise PcapNotIP
            else:
                print("[dropped %04x / %d]..." % (sll.ethtype, sll.type),
                      end="", sep="", file=sys.stderr)
                raise PcapNotIP

        return f

    elif dlt == dpkt.pcap.DLT_EN10MB:
        return lambda bs: dpkt.ethernet.Ethernet(bs).data

    else:
        print(dlt, file=sys.stderr)

if __name__ == "__main__":

    p = argparse.ArgumentParser(
        description="Convert BGP packets in a PCAP to MRTD.")
    p.add_argument('INPUT', help="PCAP file to analyse")
    p.add_argument('-p', '--port', dest="PORT", default=179, type=int,
                   help="Port number to treat as BGP")
    args = p.parse_args()

    with open(args.INPUT, 'rb') as f:
        pcap = R(f)
        _ip = ip_getter(pcap)
        for ts, hdr, buf in pcap:
            try:
                ip = _ip(buf)
            except PcapNotIP as e:
                print(e, file=sys.stderr)
                continue

            if not isinstance(ip, dpkt.ip.IP): continue
            tcp = ip.data

            if not isinstance(tcp, dpkt.tcp.TCP): continue
            if tcp.dport == args.PORT or tcp.sport == args.PORT:
                print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
                      (ip.src, ip.dst, ip.len, ip.ttl, ip.df, ip.mf, ip.off))

                ## now need to reassemble the TCP stream to extract the BGP PDUs
                ## from the stream, potentially taking account of fragmentation
                ## and retransmission and so forth ...

                ## TODO
