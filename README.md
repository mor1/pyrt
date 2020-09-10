# PyRT: Python Routeing Toolkit

Copyright (C) 2001-2020 Richard Mortier <mort@cantab.net>, Sprint ATL

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

## 1. Purpose

The purpose of this software is to enable routeing information in a network (ie. Sprintlink) to be collected. This package currently supports BGPv4 and ISIS and will dump MRTD format files. It also supports parsing of MRTD `TABLE_DUMP` files (as available from, eg., [RouteViews](http://archive.routeviews.org/) and [RIPE/RIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data)). A number of utilities for manipulating these dumps are also provided.

PyRT is distributed under the terms of the GNU General Public License version 2. A copy is contained within this distribution in the file [COPYING](COPYING).

## 2. Overview

All code is written in Python v2(.1.1) and was developed under Redhat 7.1. The code is split modules which may be imported and are described in detail below.

A module consists of 4 parts:

  * imports, global variables, constants, etc;
  * module exported functions available to other programs;
  * a wrapper class to abstract communication details and lower layers;
  * an entry point (`if __name__ == "__main__": <code>`).

Protocol modules contain all 4 parts; other modules may not.

It was tested against Zebra 0.91a and a CISCO 7xxx running IOS 12.1.

## 3. Code structure

### 3.0. [Utility functions](mutils.py)

This is a generic utility module. It provides some handy functions for manipulating IP addresses/prefixes, and for printing packed strings in
hexadecimal and binary. The naming convention is:

  * `mask2plen`/`addrmask2str`: manipulate and print address/mask prefixes (as opposed to prefix/length prefixes).

  * `str2id`/`id2str`/`pfx2str`/`str2pfx`: convert between string and long representations of IP addresses/prefixes.

  * `isid2id`: given an ISIS/CLNP address, convert to the numeric representation of the corresponding IP address (assuming the standard 11.22.33.44.55.66 -> 112.233.445.566 mapping).

  * `int2xxx`: given an integer, return a string representation in base xxx.

  * `str2xxx`: given a string (ie. packed binary data a la the 'struct' module), return a string representation in base xxx.

  * `prtxxx`: print the string representation, taking care of wrapping and pretending a prefix to each line.

### 3.1. Protocol modules

These provide support for particular routeing protocols; current ISIS and BGPv4 are supported. Each exports functions for parsing messages associated with that protocol, in addition to a class which enables communication with other entities supporting that protocol for data collection purposes, and an entry point. In general, the classes do not implement protocol state machines completely, but do the minimum necessary to start receiving routeing information. Similarly, error handling is (just about) non-existant. No class will advertise any routeing information.

All protocol modules essentially work in the same manner:

```
new protocol()
initialize protocol
while 1:
   protocol.parse()
```

where the protocol constructor sets up the object, protocol initialisation involves doing whatever needs to be done to talk to an entity supporting that protocol, and protocol.parse() uses the protocol class to read the next message in appropriately, and then dump and/or print it accordingly. All listeners support 4 verbosity options:

  * quiet (`-q`): output nothing.

  * default: output human readable parsing of protocol messages.

  * verbose (`-v`): in addition to default, output significant chunks of messages in binary/hex.

  * very verbose (`-V`): in addition to above, output results/parameters of `recvMsg()`, `parseMsg()`, `sendMsg()` (mostly for debugging purposes).

#### 3.1.0. [MRTD](mrtd.py)

This module implements some generic logging functionality. It provides support for reading and writing MRTD format log files in 3 formats:

  * `PROTOCOL_BGP`:
    default for the BGP module; slightly extended to allow messages other than UPDATEs to be dumped.

  * `PROTOCOL_BGP4MP`:
    alternative BGP dump format used by Zebra. Contains hacks to work around problems in Zebra dumps (v0.89 and 0.91a).

  * `PROTOCOL_ISIS`:
    non-standard homegrown format for dumping ISIS messages.

It provides a class to wrap up dealing with reading and writing MRTD dumps. This handles details such as dump file rotation based on size limits. It also attempts to be mildly efficient by buffering reads, whilst ensuring that there is always a complete MRTD message available to be parsed. Writes are unbuffered at the present time.

It also supports (with the aid of the BGP module) parsing of `MRTD TABLE_DUMP` files.

#### 3.1.1. [BGP v4](bgp.py)

This module implements the BGP listener. It provides extensive parsing support, but implements a highly restricted subset of the state machine. Essentially:

```
initialize
socket connect to remote end

send OPEN
receive OPEN
send KEEPALIVE ## remote end should be ESTABLISHED at this point

while 1:
    parse message
```

Although all messages are parsed, `NOTIFY`s are not obeyed, and in normal operation we expect to receive only `UPDATE`s, and transmit nothing, after the connection becomes `ESTABLISHED`. If an error occurs at any point, the script will either exit gracelessly or sit there waiting forever, and need to be restarted.

A note on `bgp.recvMsg()`: this tries to be (slightly) cunning. Since BGP PDUs are transported over TCP (a byte-stream with no PDU boundary information), we have to ensure that we read enough data off the socket to get a complete BGP PDU. This is done by repeatedly reading into a per-instance buffer until we are sure that there is enough data in the buffer that the complete PDU can be recovered. This has managed to be the most bug-ridden part of this module so far, so watch out...

Eg.
```
: $; ./bgp.py -p 10.64.233.1 -a 200 --local 10.64.233.42 -m \
              -f bgp-dump -z $((1024*1024*5))
```

#### 3.1.2. [ISIS](isis.py)

The module implements the ISIS listener. It provides parsing support for most ISIS messages, and implements as little of the state machine as I could (damn those ISO protocol writers for being too good :-)). None of the clever stuff about rate limiting transmissions, jittering timers, and so on is performed (we should never be transmitting so many packets that anyone would care). Essentially it forms a single adjacency with the router to which the machine is physically connected. This adjacency is maintained as mandated using `HELLO`s (currently only LAN `HELLO`s are supported). It then listens for and dumps all packets received and transmitted. Basically:

```
while 1:
    select on (message-to-read, timeout-expired)

    if message-to-read:
        Isis.parseMsg()

    else: ## we need to transmit one or more packets
        for-each adjacency:
            if required:
                transmit ISIS HELLO
            update timeout
```

Since ISIS is transported directly in zero padded 802.2 frames, message boundaries are frame boundaries so we don't need any buffering cunningness a la BGP. However, since we have 802.2 frames, messages are retrieved via a raw socket (`PF_PACKET`, `SOCK_RAW`), the reason this listener requires Python v2(.1.1). See the comment at the start of the module for an explanation of the MAC/LLC encapsulation used.

Eg.

```
: $; ./isis.py -d -a 49.00.01 -z $((1024*1024*5)) -f isis-dump
```

#### 3.1.3. [OSPF](ospf.py)

This module implements the OSPF listener, blah, as for the ISIS module :)

### 3.2. Utilities

In addition to the example parse.py, a small number of utilities are also provided in the scripts subdirectory. In no particular order:

#### 3.2.0. [parse.py](parse.py)

Dummy script that demonstrates basic use of the MRTD/protocol libraries and dictionary return formats.

#### 3.2.1. [splice.py](splice.py)

This takes a number of MRTD files on the command line, and splices their messages together in time order (breaking ties by the order they appeared on the command line). It can output to files of a given size, using the same rotation algorithm as the MRTD module.

#### 3.2.2. [clean.py](clean.py)

This cleans a trace file, ensuring that a valid rv is returned for each message (at least, an rv with non-None "T" field).

## 4. References

### BGP

  * "BGP4: Inter-domain routing in the Internet" John W. Stewart III

  * RFC 1771 (base)
  * RFC 1965 (confederations)
  * RFC 1966 (route reflectors)
  * RFC 1997 (communities)
  * RFC 2283, RFC 2858 (multi-protocol extensions)
  * RFC 2842 (capabilities advertisement)
  * RFC 2918 (route refresh)

  * draft-ietf-idr-cease-subcode-00.txt (cease notification subcodes)
  * draft-ietf-idr-bgp-ext-communities-01.txt (extended communities)

### MRTD

  * <http://www.mrtd.net/>
  * Zebra documentation


#### ISIS

  * RFC 1142 (OSI ISO ISIS)
  * RFC 1195 (IP extensions)
  * RFC 2763 (Dynamic hostname TLV)
  * <http://www.gated.org/>
    GateD public release v3.5.11 (the last to support ISIS, and then only on NetBSD)
  * <http://www.rware.demon.co.uk/isis.htm>
    magic numbers, MAC/LLC headers

  * <http://www.cisco.com/warp/public/97/tlvs_5739.html>
  * [Zebra](http://www.zebra.org/)

## 5. TODO

  * need to _completely_ separate the parsing from pretty printing
  * ext timestamp support is ugly -- should push into common header
  * bgp: support KEEPALIVEs for robustness

  * write buffering
  * bgp: support multiple peering sessions
  * isis: fix the finding of the IP address (ie. make -i obsolete)
