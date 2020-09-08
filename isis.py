#! /usr/bin/env python2.5

##     PyRT: Python Routeing Toolkit

##     ISIS module: provides ISIS listener and ISIS PDU parsers

##     Copyright (C) 2001 Richard Mortier <mort@sprintlabs.com>, Sprint ATL

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

# refs: http://www.rware.demon.co.uk/isis.htm, RFC1195, RFC1142,

# This is a good deal grimmer than the BGP module since ISIS, by default on
# Ethernet/802.3 links, is encapsulated directly within the frame.  As a
# consequence we need PF_PACKET and SOCK_RAW to get it -- THESE ARE ONLY
# SUPPORTED IN PYTHON >= 2.0.  As a result this will not be as portable as I'd
# like.  Stick to Linux 2.2.x and higher kernels with packet sockets
# (CONFIG_PACKET) enabled; I've tested on RH7.1 std. install.  Also, it must
# run as root :-((

# Explanation of which bits we slurp: we are looking for ISIS packets carried
# in IEEE 802.3 frames.  This means that we have the following octet layout:

# MAC header (IEEE 802.3):

#   ss-ss-ss-ss-ss-ss :: <6:src MAC>
#   dd-dd-dd-dd-dd-dd :: <6:dst MAC>
#   ll-ll             :: <2:length> == 0x05dc == 1500 (payload only)

# LLC header (IEEE 802.2):
#   dsap :: <1:DSAP> == 0xfe ...by RFC1340, p53, "IEEE 802 Numbers of interest"
#   ssap :: <1:SSAP> == 0xfe ...("ISO CLNS IS 8473")
#   ctrl :: <1 or 2: control> == 0x03 ("unnumbered information")

# In fact, from (after some moulinexing :-)
# http://cell-relay.indiana.edu/cell-relay/docs/rfc/1483/1483.4.1.html

# In LLC Encapsulation the protocol of the routed PDU is identified by
# prefixing the PDU by an IEEE 802.2 LLC header, which is possibly followed by
# an IEEE 802.1a SubNetwork Attachment Point (SNAP) header. ...  The presence
# of a SNAP header is indicated by the LLC header value 0xAA-AA-03.

# ...

# The LLC header value 0xFE-FE-03 identifies that a routed ISO PDU (see [6]
# and Appendix B) follows. The Control field value 0x03 specifies Unnumbered
# Information Command PDU.  ... The routed ISO protocol is identified by a one
# octet NLPID field that is part of Protocol Data. NLPID values are
# administered by ISO and CCITT. They are defined in ISO/IEC TR 9577 [6] and
# some of the currently defined ones are listed in Appendix C.

# ...

# Appendix C. Partial List of NLPIDs
#  0x00    Null Network Layer or Inactive Set (not used with ATM)
#  0x80    SNAP
#  0x81    ISO CLNP
#  0x82    ISO ESIS
#  0x83    ISO ISIS
#  0xCC    Internet IP

# ie. we have 14 octets MAC header, 3 octets LLC header, and then we are in
# the ISIS packet, starting with the NLPID 0x83.  Phew.

# Note 1: AFI 49 (pfx on area code) is public CLNS space a la 10.x.x.x in IP

# Note 2: Actually, although the intro. above says this is grimmer, it is in
# fact quite a lot nicer once adjacency is established.  ISIS is a much nicer
# protocol than BGP which sucks high vacuum.

import sys, getopt, socket, string, os.path, struct, time, select, math
from mutils import *

#-------------------------------------------------------------------------------

VERSION = "3.0"
INDENT  = "    "

RETX_THRESH = 1
RCV_BUF_SZ  = 2048

MAC_PKT_LEN  = 1514
MAC_HDR_LEN  = 17
ISIS_PKT_LEN = 1500
ISIS_PDU_LEN = ISIS_PKT_LEN-3
ISIS_LLC_HDR = (0xfe, 0xfe, 0x03, 0x83)

ISIS_HDR_LEN       =  8
ISIS_HELLO_HDR_LEN = 19
ISIS_LSP_HDR_LEN   = 19
ISIS_CSN_HDR_LEN   = 25
ISIS_PSN_HDR_LEN   =  9

AllL1ISs = struct.pack("6B", 0x01, 0x80, 0xc2, 0x00, 0x00, 0x14)
AllL2ISs = struct.pack("6B", 0x01, 0x80, 0xc2, 0x00, 0x00, 0x15)

################################################################################

DLIST = []

NLPIDS = { 0x00: "NULL",
           0x80: "SNAP",
           0x81: "CLNP",
           0x82: "ESIS",
           0x83: "ISIS",
           0x8E: "IPV6",
           0xCC: "IP",
           }
DLIST = DLIST + [NLPIDS]

MSG_TYPES = { 0:  "NULL",
              2:  "ESH",
              4:  "ISH",
              6:  "RD",
              15: "L1LANHello",
              16: "L2LANHello",
              17: "PPHello",
              18: "L1LSP",
              20: "L2LSP",
              24: "L1CSN",
              25: "L2CSN",
              26: "L1PSN",
              27: "L2PSN",
              }
DLIST = DLIST + [MSG_TYPES]

CIRCUIT_TYPES = { 0: "reserved", # ignore entire PDU
                  1: "L1Circuit",
                  2: "L2Circuit",
                  3: "L1L2Circuit",
                  }
DLIST = DLIST + [CIRCUIT_TYPES]

FLAGS = {1: "SUPPORT_IP",
         2: "SUPPORT_CLNP",
         }
DLIST = DLIST + [FLAGS]

VLEN_FIELDS = { 0:   "Null",                # null
                1:   "AreaAddress",         # area address
                2:   "LSPIISNeighbor",      # ISIS (CLNP) neighbour (in LSP)
                3:   "ESNeighbor",          # end system (CLNP) neighbour
                4:   "PartDIS",             #
                5:   "PrefixNeighbor",      #
                6:   "IIHIISNeighbor",      # ISIS (CLNP) neighbour (in ISH)
                8:   "Padding",             # zero padding
                9:   "LSPEntries",          # LSPs ack'd in this CSNP/PSNP
                10:  "Authentication",      #
                12:  "OptionalChecksum",    #
                14:  "LSPBufferSize",       #

                22:  "TEIISNeighbor",       #

                128: "IPIntReach",          # 'internal' reachable IP subnets
                129: "ProtoSupported",      # NLPIDs this IS can relay
                130: "IPExtReach",          # 'external' reachable IP subnets
                131: "IPInterDomInfo",      # interdomain routeing info
                132: "IPIfAddr",            # IP address(es) of the interface
                133: "IPAuthInfo_ILLEGAL",  # deprecated
                134: "TERouterID",          # TE router ID
                135: "TEIPReach",           # 'wide metric TLV'
                137: "DynamicHostname",     # dynamic hostname support

                180: "LeafNode",            #

                222: "MultipleTopologyISN", #
                229: "MultipleTopologies",  #
                232: "IPv6IfAddr",          #
                235: "MTIPReach",           #
                236: "IPv6IPReach",         #
                240: "ThreeWayHello",       #

                254: "IPSumReach",          #
                }
DLIST = DLIST + [VLEN_FIELDS]

STATES = { 0: "NULL",
           1: "INITIALISING",
           2: "UP",
           3: "DOWN",
           }
DLIST = DLIST + [STATES]

for d in DLIST:
    for k in list(d.keys()):
        d[ d[k] ] = k

################################################################################

def padPkt(tgt_len, pkt):

    pad_len = tgt_len - len(pkt)
    if pad_len > 0:
        full, part = divmod(pad_len, 257)

        pkt = pkt + (full*struct.pack("BB 255s",
                                 VLEN_FIELDS["Padding"], 255, 255*'\000'))
        pkt = pkt + struct.pack("BB %ds" % (part-2, ),
                           VLEN_FIELDS["Padding"], part-2, (part-2)*'\000')
    return pkt

#-------------------------------------------------------------------------------

def parseMacHdr(pkt):

    (dst_mac, src_mac, length, dsap, ssap, ctrl, nlpid) =\
              struct.unpack(">6s 6s H B B B B", pkt[0:MAC_HDR_LEN+1])

    if (dsap, ssap, ctrl, nlpid) != ISIS_LLC_HDR:
        raise LLCExc

    return (src_mac, dst_mac, length, dsap, ssap, ctrl)

#-------------------------------------------------------------------------------

def parseIsisHdr(pkt):

    (nlpid, hdr_len, ver_proto_id, resvd, msg_type, ver, eco, user_eco) =\
            struct.unpack(">8B", pkt[0:ISIS_HDR_LEN])

    return (nlpid, hdr_len, ver_proto_id, resvd,
            msg_type, ver, eco, user_eco)

#-------------------------------------------------------------------------------

def parsePsnHdr(pkt):

    (pdu_len, src_id) = struct.unpack("> H 7s", pkt[:ISIS_PSN_HDR_LEN])

    return (pdu_len, src_id)

#-------------------------------------------------------------------------------

def parseCsnHdr(pkt):

    (pdu_len, src_id, start_lsp_id, end_lsp_id) =\
              struct.unpack("> H 7s 8s 8s", pkt[:ISIS_CSN_HDR_LEN])

    return (pdu_len, src_id, start_lsp_id, end_lsp_id)

#-------------------------------------------------------------------------------

def parseLspHdr(pkt):

    (pdu_len, lifetime, lsp_id, seq_no, cksm, bits) =\
              struct.unpack("> HH 8s LHB", pkt[:ISIS_LSP_HDR_LEN])
    lsp_id = struct.unpack("> 6sBB", lsp_id)

    return (pdu_len, lifetime, lsp_id, seq_no, cksm, bits)

################################################################################

def parseIsisMsg(msg_len, msg, verbose=1, level=0):

    (src_mac, dst_mac, length, dsap, ssap, ctrl) = parseMacHdr(msg)
    (nlpid, hdr_len, ver_proto_id, resvd, msg_type, ver, eco, user_eco) =\
            parseIsisHdr(msg[MAC_HDR_LEN:MAC_HDR_LEN+ISIS_HDR_LEN])

    if verbose > 1:
        print(prtbin(level*INDENT, msg[:MAC_HDR_LEN]))

    if verbose > 0:
        print(level*INDENT +\
              "%s (len=%d):" % (MSG_TYPES[msg_type], length))
        print((level+1)*INDENT +\
              "src mac: %s, dst mac: %s" %\
              (str2hex(src_mac), str2hex(dst_mac)))
        print((level+1)*INDENT +\
              "len: %d, LLC: 0x%0.2x.%0.2x.%0.2x" %\
              (length, dsap, ssap, ctrl))

    if verbose > 1:
        print(prtbin((level+1)*INDENT,
                     msg[MAC_HDR_LEN:MAC_HDR_LEN+ISIS_HDR_LEN]))

    if verbose > 0:
        print((level+1)*INDENT +\
              "hdr_len: %d, protocol id: %d, version: %d, " %\
              (hdr_len, ver_proto_id, ver) +\
              "eco: %d, user eco: %d" % (eco, user_eco))

    rv = {"T": msg_type,
          "L": msg_len,
          "H": {},
          "V": {}
          }

    rv["H"]["SRC_MAC"] = src_mac
    rv["H"]["DST_MAC"] = dst_mac
    rv["H"]["LENGTH"]  = length
    rv["H"]["DSAP"]    = dsap
    rv["H"]["SSAP"]    = ssap
    rv["H"]["CTRL"]    = ctrl

    rv["H"]["NLPID"]        = nlpid
    rv["H"]["HDR_LEN"]      = hdr_len
    rv["H"]["VER_PROTO_ID"] = ver_proto_id
    rv["H"]["VER"]          = ver
    rv["H"]["ECO"]          = eco
    rv["H"]["USER_ECO"]     = user_eco

    msg = msg[MAC_HDR_LEN+ISIS_HDR_LEN:]
    if msg_type in list(MSG_TYPES.keys()):
        if   msg_type in (MSG_TYPES["L1LANHello"], MSG_TYPES["L2LANHello"]):
            (rv["V"]["CIRCUIT_TYPE"],
             rv["V"]["SRC_ID"],
             rv["V"]["HOLDTIMER"],
             rv["V"]["PDU_LEN"],
             rv["V"]["PRIO"],
             rv["V"]["LAN_ID"],
             rv["V"]["VFIELDS"]) = parseIsisIsh(msg_len, msg, verbose, level)

        elif msg_type == MSG_TYPES["PPHello"]:
            parseIsisPPIsh(msg_len, msg, verbose, level)

        elif msg_type in (MSG_TYPES["L1LSP"], MSG_TYPES["L2LSP"]):
            (rv["V"]["PDU_LEN"],
             rv["V"]["LIFETIME"],
             rv["V"]["LSP_ID"],
             rv["V"]["SEQ_NO"],
             rv["V"]["CKSM"],
             rv["V"]["BITS"],
             rv["V"]["VFIELDS"]) = parseIsisLsp(msg_len, msg, verbose, level)

        elif msg_type in (MSG_TYPES["L1CSN"], MSG_TYPES["L2CSN"]):
            (rv["V"]["PDU_LEN"],
             rv["V"]["SRC_ID"],
             rv["V"]["START_LSP_ID"],
             rv["V"]["END_LSP_ID"],
             rv["V"]["VFIELDS"]) = parseIsisCsn(msg_len, msg, verbose, level)

        elif msg_type in (MSG_TYPES["L1PSN"], MSG_TYPES["L2PSN"]):
            (rv["V"]["PDU_LEN"],
             rv["V"]["SRC_ID"],
             rv["V"]["VFIELDS"]) = parseIsisPsn(msg_len, msg, verbose, level)

        else:
            if verbose > 0:
                print(level*INDENT + "[ *** %s *** ]" % MSG_TYPES[msg_type])

    else:
        if verbose > 0:
            print(level*INDENT + "[ UNKNOWN ISIS message: ", repr(msg_type), " ]")

    return rv

################################################################################

def parseIsisIsh(msg_len, msg, verbose=1, level=0):

    (circuit_type, src_id, holdtimer,
     pdu_len, prio, lan_id) = struct.unpack("> B 6s H H B 7s",
                                            msg[:ISIS_HELLO_HDR_LEN])

    if verbose > 1:
        print(prtbin(level*INDENT, msg[:ISIS_HELLO_HDR_LEN]))

    if verbose > 0:
        print((level+1)*INDENT +\
              "circuit type: %s, holdtimer: %d, " %\
              (CIRCUIT_TYPES[circuit_type], holdtimer) +\
              "PDU len: %d, priority: %d" % (pdu_len, (prio&0x7f)))
        print((level+1)*INDENT + "src id: %s, LAN id: %s" %\
              (str2hex(src_id), str2hex(lan_id)))

    vfields = parseVLenFields(msg[ISIS_HELLO_HDR_LEN:], verbose, level)
    return (circuit_type, src_id, holdtimer, pdu_len, prio, lan_id, vfields)

#-------------------------------------------------------------------------------

def parseIsisPPIsh(msg_len, msg, verbose=1, level=0):

    print(level*INDENT + "[ *** PP ISH NOT PARSED *** ]")

#-------------------------------------------------------------------------------

def parseIsisLsp(msg_len, msg, verbose=1, level=0):

    (pdu_len, lifetime, lsp_id, seq_no, cksm, bits) = parseLspHdr(msg)

    if verbose > 0:

        if verbose > 1:
            print(prtbin(level*INDENT, msg[:ISIS_LSP_HDR_LEN]))
        print((level+1)*INDENT +\
              "PDU len: %d, lifetime: %d, seq.no: %d, cksm: %s" %\
              (pdu_len, lifetime, seq_no, int2hex(cksm)))
        print((level+1)*INDENT +\
              "LSP ID: src: %s, pn: %s, LSP no: %d" %\
              (str2hex(lsp_id[0]), int2hex(lsp_id[1]), lsp_id[2]))

        p   = bits & (1<<7)
        att = (bits & (1<<6)) * "error " + (bits & (1<<5)) * "expense " +\
              (bits & (1<<4)) * "delay " + (bits & (1<<3)) * "default"
        hty = (bits & (1<<2)) >> 2
        ist = bits & ((1<<1) | (1<<0))

        print((level+1)*INDENT +\
              "partition repair: %s, hippity: %s, type: %s" %\
              (("no", "yes")[p], ("no", "yes")[hty],
               ("UNUSED", "L1", "UNUSED", "L1+L2")[ist]))
        print((level+1)*INDENT + "attached: %s" % att)

    vfields = parseVLenFields(msg[ISIS_LSP_HDR_LEN:], verbose, level)
    return (pdu_len, lifetime, lsp_id, seq_no, cksm, bits, vfields)

#-------------------------------------------------------------------------------

def parseIsisCsn(msg_len, msg, verbose=1, level=0):

    (pdu_len, src_id, start_lsp_id, end_lsp_id) = parseCsnHdr(msg)

    if verbose > 0:

        if verbose > 1:
            print(prtbin(level*INDENT, msg[:ISIS_CSN_HDR_LEN]))
        print((level+1)*INDENT +\
              "PDU len: %d, src ID: %s" % (pdu_len, str2hex(src_id)))
        print((level+1)*INDENT +\
              "start LSP ID: %s" % (str2hex(start_lsp_id),))
        print((level+1)*INDENT +\
              "end LSP ID: %s" % (str2hex(end_lsp_id),))

    vfields = parseVLenFields(msg[ISIS_CSN_HDR_LEN:], verbose, level)
    return (pdu_len, src_id, start_lsp_id, end_lsp_id, vfields)

#-------------------------------------------------------------------------------

def parseIsisPsn(msg_len, msg, verbose=1, level=0):

    (pdu_len, src_id) = parsePsnHdr(msg)

    if verbose > 0:

        if verbose > 1:
            print(prtbin(level*INDENT, msg[:ISIS_PSN_HDR_LEN]))
        print((level+1)*INDENT +\
              "PDU len: %d, src ID: %s" % (pdu_len, str2hex(src_id)))

    vfields = parseVLenFields(msg[ISIS_PSN_HDR_LEN:], verbose, level)
    return (pdu_len, src_id, vfields)

################################################################################

def parseVLenFields(fields, verbose=1, level=0):

    vfields = {}

    while len(fields) > 1:
        # XXX: strange -- have seen single null byte vfields...

        (ftype, flen) = struct.unpack(">BB", fields[0:2])

        if ftype not in vfields:
            vfields[ftype] = []

        vfields[ftype].append(
            parseVLenField(ftype, flen, fields[2:2+flen], verbose, level+1)
            )

        fields = fields[2+flen:]

    return vfields

#-------------------------------------------------------------------------------

def parseVLenField(ftype, flen, fval, verbose=1, level=0):

    rv = { "L" : flen,
           }

    if verbose > 1 and ftype not in (VLEN_FIELDS["Padding"],
                                     VLEN_FIELDS["Null"]):
        print(prtbin(level*INDENT, repr(ftype)+repr(flen)+fval))

    if ftype in list(VLEN_FIELDS.keys()):
        if verbose > 0 and ftype not in (VLEN_FIELDS["Padding"],
                                         VLEN_FIELDS["Null"]):
            print(level*INDENT +\
                  "field: %s, length: %d" % (VLEN_FIELDS[ftype], flen))

        level = level + 1
        if   ftype == VLEN_FIELDS["Null"]:
            pass

        elif ftype == VLEN_FIELDS["AreaAddress"]:
            ## 1
            rv["V"] = []
            areas = ""
            while len(fval) > 0:

                (l,) = struct.unpack("> B", fval[0])

                rv["V"].append(fval[1:1+l])

                areas = areas + '0x' + str2hex(fval[1:1+l]) + ", "
                fval = fval[1+l:]

            if verbose > 0:
                print(level*INDENT + "area addresses: " + areas)

        elif ftype == VLEN_FIELDS["LSPIISNeighbor"]:
            ## 2
            rv["V"] = []
            vflag = struct.unpack("> B", fval[0])
            fval  = fval[1:]
            cnt   = 0
            while len(fval) > 0:
                cnt = cnt + 1
                default, delay, expense, error, nid =\
                         struct.unpack("> BBBB 7s", fval[0:11])

                is_neighbour = { 'DEFAULT': default,
                                 'DELAY'  : delay,
                                 'EXPENSE': expense,
                                 'ERROR'  : error,
                                 'NID'    : nid,
                                 }
                rv["V"].append(is_neighbour)

                if verbose > 0:
                    print(level*INDENT +\
                          "IS Neighbour %d: id: %s" % (cnt, str2hex(nid)))
                    print((level+1)*INDENT +\
                          "default: %d, delay: %d, expense: %d, error: %d" %\
                          (default, delay, expense, error))

                fval = fval[11:]

        elif ftype == VLEN_FIELDS["ESNeighbor"]:
            ## 3
            default, delay, expense, error = struct.unpack("> 4B", fval[0:4])
            rv["V"] = { 'DEFAULT' : default,
                        'DELAY'   : delay,
                        'EXPENSE' : expense,
                        'ERROR'   : error,
                        'NIDS'    : []
                        }

            if verbose > 0:
                print(level*INDENT +\
                      "default: %d, delay: %d, expense: %d, error: %d" %\
                      (default, delay, expense, error))

            fval = fval[4:]
            cnt  = 0
            while len(fval) > 0:
                cnt = cnt + 1
                (nid,) = struct.unpack("> 6s", fval[0:6])

                rv["V"]["NIDS"].append(nid)

                if verbose > 0:
                    print(level*INDENT +\
                          "ES Neighbour %d: %s" % (cnt, str2hex(nid)))

                fval = fval[6:]

        elif ftype == VLEN_FIELDS["IIHIISNeighbor"]:
            ## 6
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                (nid,) = struct.unpack("> 6s", fval[0:6])

                rv["V"].append(nid)

                if verbose > 0:
                    print(level*INDENT +\
                          "IS Neighbour %d: %s" % (cnt, str2hex(nid)))

                fval = fval[6:]

        elif ftype == VLEN_FIELDS["Padding"]:
            ## 8
            rv["V"] = None

        elif ftype == VLEN_FIELDS["LSPEntries"]:
            ## 9
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                lifetime, lsp_id, lsp_seq_no, cksm =\
                          struct.unpack("> H 8s L H", fval[:16])
                lsp_id = struct.unpack("> 6sBB", lsp_id)

                lsp_entry = { "ID"       : lsp_id[0],
                              "PN"       : lsp_id[1],
                              "NM"       : lsp_id[2],
                              "LIFETIME" : lifetime,
                              "SEQ_NO"   : lsp_seq_no,
                              "CKSM"     : cksm
                              }

                rv["V"].append(lsp_entry)

                if verbose > 0:
                    print(level*INDENT +\
                          "%d: LSP ID: src: %s, pn: %s, LSP no: %d" %\
                          (cnt, str2hex(lsp_id[0]), int2hex(lsp_id[1]), lsp_id[2]))
                    print((level+1)*INDENT +\
                          "lifetime: %d, seq.no: %d, cksm: %s" %\
                          (lifetime, lsp_seq_no, int2hex(cksm)))

                fval = fval[16:]

        elif ftype == VLEN_FIELDS["IPIntReach"]:
            ## 128
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                default, delay, expense, error, addr, mask =\
                         struct.unpack("> 4B LL", fval[0:12])

                ipif = { 'DEFAULT': default,
                         'DELAY'  : delay,
                         'EXPENSE': expense,
                         'ERROR'  : error,
                         'ADDR'   : addr,
                         'MASK'   : mask
                         }
                rv["V"].append(ipif)

                if verbose > 0:
                    print(level*INDENT +\
                          "%d: default: %d, delay: %d, expense: %d, error: %d" %\
                          (cnt, default, delay, expense, error))
                    print((level+1)*INDENT +\
                          "addr/mask: %s/%s" % (id2str(addr), id2str(mask)))

                fval = fval[12:]

        elif ftype == VLEN_FIELDS["ProtoSupported"]:
            ## 129
            prots = struct.unpack("> %dB" % flen, fval)
            prots_strs = ['%s' % x for x in [NLPIDS[x] for x in prots]]

            rv["V"] = prots_strs

            if verbose > 0:
                print(level*INDENT + "protocols supported: " + repr(prots_strs))

        elif ftype == VLEN_FIELDS["IPExtReach"]:
            ## 130
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                default, delay, expense, error, addr, mask =\
                         struct.unpack("> 4B LL", fval[0:12])

                ipif = { 'DEFAULT': default,
                         'DELAY'  : delay,
                         'EXPENSE': expense,
                         'ERROR'  : error,
                         'ADDR'   : addr,
                         'MASK'   : mask
                         }
                rv["V"].append(ipif)

                if verbose > 0:
                    print(level*INDENT +\
                          "%d: default: %d, delay: %d, expense: %d, error: %d" %\
                          (cnt, default, delay, expense, error))
                    print((level+1)*INDENT +\
                          "addr/mask: %s/%s" % (id2str(addr), id2str(mask)))

                fval = fval[12:]

        elif ftype == VLEN_FIELDS["IPInterDomInfo"]:
            ## 131
            rv["V"] = None

            if verbose > 0:
                print(level*INDENT + "[ IPInterDomInfo ]")

        elif ftype == VLEN_FIELDS["IPIfAddr"]:
            ## 132
            addrs = struct.unpack("> %dL" % (flen/4, ), fval)
            addrs_strs = [id2str(x) for x in addrs]

            rv["V"] = addrs_strs
            if verbose > 0:
                print(level*INDENT + "interface IP addresses: " + repr(addrs_strs))

        elif ftype == VLEN_FIELDS["DynamicHostname"]:
            ## 137
            name = struct.unpack("> %ds" % flen, fval)
            rv["V"] = name

            if verbose > 0:
                print(level*INDENT + "dynamic hostname: '%s'" % name)

        else:
            if verbose > 0:
                print(level*INDENT + "[ *** %s *** ]" % VLEN_FIELDS[ftype])

    else:
        if verbose > 0:
            print(level*INDENT + \
                  "[ UNKNOWN ISIS variable length field: ", repr(ftype), " ]")

    return rv

################################################################################

class LLCExc(Exception): pass
class VLenFieldExc(Exception): pass

#-------------------------------------------------------------------------------

class Isis:

    _eth_p_802_2 = socket.htons(0x0004)
    _dev_str     = "eth0"

    _version          = 1
    _version_proto_id = 1

    _hold_multiplier  = 3
    _holdtimer        = 10

    #---------------------------------------------------------------------------

    class Adj:

        def __init__(self, atype, rx_ish, tx_ish):

            self._state  = STATES["INITIALISING"]
            self._type   = atype
            self._tx_ish = tx_ish
            self._rx_ish = rx_ish

            self._rtx_at = 0

            (src_mac, _, _, _, _) = parseMacHdr(rx_ish)
            self._nbr_mac_addr = src_mac

            hdr_start = MAC_HDR_LEN + ISIS_HDR_LEN
            hdr_end   = hdr_start + ISIS_HELLO_HDR_LEN
            (_, src_id, ht, _, prio, lan_id) =\
                   struct.unpack(">B 6s H H B 7s", rx_ish[hdr_start:hdr_end])

            self._holdtimer  = ht
            self._nbr_src_id = src_id
            self._nbr_lan_id = lan_id

            self._nbr_areas = []
            fields = rx_ish[MAC_HDR_LEN+ISIS_HDR_LEN+ISIS_HELLO_HDR_LEN:]
            while len(fields) > 0:

                (ftype, flen) = struct.unpack(">BB", fields[0:2])
                fval          = fields[2:2+flen]
                if ftype == VLEN_FIELDS["AreaAddress"]:
                    while len(fval) > 0:
                        (l,) = struct.unpack("B", fval[0])
                        self._nbr_areas.append(fval[1:1+l])
                        fval = fval[1+l:]

                fields = fields[2+flen:]

        def __repr__(self):

            ret = """st: %s, ht: %d, retx: %d, neighbour areas: %s,
            nbr src id: %s, lan id: %s""" %\
            (STATES[self._state], self._holdtimer, self._rtx_at,
             repr(list(map(str2hex, self._nbr_areas))),
             str2hex(self._nbr_src_id), str2hex(self._nbr_lan_id))

            return ret

    #---------------------------------------------------------------------------

    def __init__(self, dev, area_addr, src_id=None, lan_id=None, src_ip=None):

        self._sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                                   Isis._eth_p_802_2)
        self._sockaddr = (dev, 0x0000)
        self._sock.bind(self._sockaddr)
        self._sockname = self._sock.getsockname()

        # XXX HACK: want to query _sock for IP addr; can't figure out
        # how at the moment
        if src_ip:
            self._src_ip = src_ip
        else:
            self._src_ip = str2id(socket.gethostbyname(socket.gethostname()))

        self._src_mac   = self._sockname[-1]
        self._area_addr = area_addr

        if src_id:
            self._src_id = src_id
        else:
            self._src_id = self._src_mac

        if lan_id:
            self._lan_id = lan_id
        else:
            self._lan_id = self._src_id + '\001'

        self._adjs  = { }
        self._rcvd  = ""
        self._mrtd  = None

    def __repr__(self):

        ret = """Passive ISIS speaker, version %s:
        Src IP: %s, Src MAC: %s
        Area address: %s
        Src ID: %s
        LAN ID: %s
        Adjs: %s\n""" %\
            (VERSION,
             id2str(self._src_ip), str2hex(self._src_mac),
             str2hex(self._area_addr), str2hex(self._src_id),
             str2hex(self._lan_id), repr(self._adjs))

        return ret

    def close(self):

        self._sock.close()
        self._mrtd.close()

    #---------------------------------------------------------------------------

    def recvMsg(self, verbose=1, level=0):

        self._rcvd = self._sock.recv(RCV_BUF_SZ)
        (src_mac, dst_mac, length, dsap, ssap, ctrl) = parseMacHdr(self._rcvd)

        if verbose > 2:
            print("%srecvMsg: recv: len=%d%s" %\
                  (level*INDENT,
                   len(self._rcvd), prthex((level+1)*INDENT, self._rcvd)))

        if verbose > 1:
            print("%srecvMsg: src: %s\n         dst: %s" %\
                  (level*INDENT, str2hex(src_mac), str2hex(dst_mac)))
            print("         len: %d" % (length, ))
            print("         dsap: %#0.2x, ssap: %#0.2x, ctl: %#0.2x" %\
                  (dsap, ssap, ctrl))

        return (len(self._rcvd), self._rcvd)

    def sendMsg(self, pkt, verbose=1, level=0):

        (src_mac, dst_mac, length, dsap, ssap, ctrl) = parseMacHdr(pkt)
        (nlpid, hdr_len, ver_proto_id, resvd,
         msg_type, ver, eco, user_eco) = parseIsisHdr(pkt)

        if DUMP_MRTD == 1:
            self._mrtd.writeIsisMsg(msg_type, len(pkt), pkt)

        elif DUMP_MRTD == 2:
            self._mrtd.writeIsis2Msg(msg_type, len(pkt), pkt)

        if verbose > 2:
            print("%ssendMsg: send: len=%d%s" %\
                  (level*INDENT, len(pkt), prthex((level+1)*INDENT, pkt)))

        if verbose > 1:
            print("%ssendMsg: src: %s\n         dst: %s" %\
                  (level*INDENT, str2hex(src_mac), str2hex(dst_mac)))
            print("         len: %d" % (length, ))
            print("         dsap: %#0.2x, ssap: %#0.2x, ctl: %#0.2x" %\
                  (dsap, ssap, ctrl))

        if verbose > 0:
            parseIsisMsg(len(pkt), pkt, verbose, level)

        if len(pkt) <= MAC_PKT_LEN:
            self._sock.send(pkt)

    def parseMsg(self, verbose=1, level=0):

        try:
            (msg_len, msg) = self.recvMsg(verbose, level)

        except (LLCExc):
            if verbose > 1:
                print("[ *** Non ISIS frame received *** ]")
            return

        (nlpid, hdr_len, ver_proto_id, resvd,
         msg_type, ver, eco, user_eco) = parseIsisHdr(msg)

        if DUMP_MRTD == 1:
            self._mrtd.writeIsisMsg(msg_type, msg_len, msg)

        elif DUMP_MRTD == 2:
            self._mrtd.writeIsis2Msg(msg_type, msg_len, msg)

        if verbose > 2:
            print("%sparseMsg: len=%d%s" %\
                  (level*INDENT, msg_len, prthex((level+1)*INDENT, msg)))

        rv = parseIsisMsg(msg_len, msg, verbose, level)
        self.processFsm(msg, verbose, level)

        return rv

    #---------------------------------------------------------------------------

    def mkMacHdr(self, dst_mac, src_mac):

        hdr = struct.pack(">6s 6s H 3B ", dst_mac, src_mac, ISIS_PKT_LEN,
                          ISIS_LLC_HDR[0], ISIS_LLC_HDR[1], ISIS_LLC_HDR[2])
        return hdr

    def mkIsisHdr(self, msg_type, hdr_len):

        nlpid = NLPIDS["ISIS"]
        ret   = struct.pack("8B", nlpid, hdr_len, Isis._version_proto_id,
                            0, msg_type, Isis._version, 0, 0)
        return ret

    def mkIshHdr(self, circuit, src_id, holdtimer, pdu_len, prio, lan_id):

        ret = struct.pack(">B 6s H H B 7s",
                          circuit, src_id, holdtimer, pdu_len, prio, lan_id)
        return ret

    def mkVLenField(self, ftype_str, flen, fval=None):

        ftype = VLEN_FIELDS[ftype_str]
        ret = struct.pack("2B", ftype, flen)
        if   ftype == VLEN_FIELDS["AreaAddress"]:
            for i in range(len(fval)):
                ret = ret +\
                      struct.pack("B %ds" % fval[i][0], fval[i][0], fval[i][1])

        elif ftype == VLEN_FIELDS["Padding"]:
            return padPkt(flen+2, "")

        elif ftype == VLEN_FIELDS["ProtoSupported"]:
            for i in range(flen):
                ret = ret + struct.pack("B", fval[i])

        elif ftype == VLEN_FIELDS["IPIfAddr"]:
            for i in range(flen/4):
                ret = ret + struct.pack(">L", fval[i])

        elif ftype == VLEN_FIELDS["IIHIISNeighbor"]:
            for i in range(flen/6):
                ret = ret + struct.pack("6s", fval[i])

        else:
            raise VLenFieldExc

        return ret

    def mkIsh(self, ln, lan_id, holdtimer):

        isns = []
        if ln == 1:
            dst_mac = AllL1ISs
            for adj in list(self._adjs.keys()):
                if 1 in self._adjs[adj]:
                    isns.append(str2mac(adj))

            msg_type = MSG_TYPES["L1LANHello"]

        elif ln == 2:
            dst_mac = AllL2ISs
            for adj in list(self._adjs.keys()):
                if 2 in self._adjs[adj]:
                    isns.append(str2mac(adj))

            msg_type = MSG_TYPES["L2LANHello"]

        ish = self.mkMacHdr(dst_mac, self._src_mac)
        ish = ish + self.mkIsisHdr(msg_type, ISIS_HDR_LEN + ISIS_HELLO_HDR_LEN)

        prio = 0 # we don't ever want to be elected Designated System
        ish  = ish + self.mkIshHdr(CIRCUIT_TYPES["L1L2Circuit"], self._src_id,
                             holdtimer, ISIS_PDU_LEN, prio, lan_id)

        ish = ish + self.mkVLenField("ProtoSupported", 1, (NLPIDS["IP"],))
        ish = ish + self.mkVLenField("AreaAddress", 1+len(self._area_addr),
                                ((len(self._area_addr), self._area_addr),))
        ish = ish + self.mkVLenField("IPIfAddr", 4, (self._src_ip,))

        if len(isns) > 0:
            ish = ish + self.mkVLenField("IIHIISNeighbor", len(isns)*6, isns)
        ish  = padPkt(MAC_PKT_LEN, ish)

        return ish

    ############################################################################

    def processFsm(self, msg, verbose=1, level=0):

        (src_mac, _, _, _, _) = parseMacHdr(msg)
        (_, _, _, _, msg_type, _, _, _) = parseIsisHdr(msg[MAC_HDR_LEN:])

        hdr_start = MAC_HDR_LEN + ISIS_HDR_LEN
        hdr_end   = hdr_start + ISIS_HELLO_HDR_LEN
        (_, src_id, _, _, _, lan_id) =\
               struct.unpack("> B 6s H H B 7s", msg[hdr_start:hdr_end])

        smac = str2hex(src_mac)
        if smac not in self._adjs:
            self._adjs[smac] = { }

        if msg_type in (MSG_TYPES["L1LANHello"], MSG_TYPES["L2LANHello"]):

            k = msg_type - 14 # L1 or L2?
            if k not in self._adjs[smac]:
                # new adjacency
                adj = Isis.Adj(k, msg, self.mkIsh(k, self._lan_id, Isis._holdtimer))
                self._adjs[smac][k] = adj

            else:
                # existing adjacency
                adj = self._adjs[smac][k]
                adj._state = STATES["UP"]
                adj._rx_ish = msg
                adj._tx_ish = self.mkIsh(k, lan_id,
                                         Isis._holdtimer*Isis._hold_multiplier)

            if adj._rtx_at <= RETX_THRESH:
                self.sendMsg(adj._tx_ish, verbose, level)

        else:
            pass

    #---------------------------------------------------------------------------

################################################################################

if __name__ == "__main__":

    import mrtd

    #---------------------------------------------------------------------------

    global VERBOSE, DUMP_MRTD

    VERBOSE   = 1
    DUMP_MRTD = 0

    file_pfx  = mrtd.DEFAULT_FILE
    file_sz   = mrtd.DEFAULT_SIZE
    mrtd_type = None
    area_addr = None
    src_id    = None
    lan_id    = None

    #---------------------------------------------------------------------------

    def usage():

        print("""Usage: %s [ options ] where options are ([*] required):
        -h|--help       : Help
        -v|--verbose    : Be verbose
        -q|--quiet      : Be quiet

        -a|--area-addr  : set the area address to which this IS belongs
        -i|--ip-addr    : *** HACK *** set the IP address to advertise
        -s|--src-id     : set the source ID of this IS
        -l|--lan-id     : set the LAN ID of this IS (def: "<srcid>:01")

        --device        : Set the device to receive on (def: %s)

        -d|--dump       : Dump MRTd::PROTOCOL_ISIS format
        -y|--dump-isis2 : Dump MRTd::PROTOCOL_ISIS2 format
        -f|--file       : Set file prefix for MRTd dump (def: %s)
        -z|--size       : Size of output file(s) (min: %d)""" %\
            (os.path.basename(sys.argv[0]), Isis._dev_str,
             mrtd.DEFAULT_FILE, mrtd.MIN_FILE_SZ))
        sys.exit(0)

    #---------------------------------------------------------------------------

    if len(sys.argv) < 2:
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hqvVdyf:s:l:a:z:i:",
                                   ("help", "quiet", "verbose", "VERBOSE",
                                    "dump", "dump-isis2",
                                    "file-pfx=", "file-size=", "device=",
                                    "src-id=", "lan-id=", "area-addr=", "ip-addr=" ))
    except (getopt.error):
        usage()

    for (x, y) in opts:
        if x in ('-h', '--help'):
            usage()

        elif x in ('-q', '--quiet'):
            VERBOSE = 0

        elif x in ('-v', '--verbose'):
            VERBOSE = 2

        elif x in ('-V', '--VERBOSE'):
            VERBOSE = 3

        elif x in ('-d', '--dump'):
            DUMP_MRTD = 1
            mrtd_type = mrtd.MSG_TYPES["PROTOCOL_ISIS"]

        elif x in ('-y', '--dump-isis2'):
            DUMP_MRTD = 2
            mrtd_type = mrtd.MSG_TYPES["PROTOCOL_ISIS2"]

        elif x in ('-f', '--file-pfx'):
            file_pfx = y

        elif x in ('--device', ):
            Isis._dev_str = y

        elif x in ('-s', '--src-id'):
            src_id = [int(x, 16) for x in string.split(y, '.')]
            src_id = struct.pack("6B",
                                 src_id[0], src_id[1], src_id[2],
                                 src_id[3], src_id[4], src_id[5])

        elif x in ('-l', '--lan-id'):
            lan_id = [int(x, 16) for x in string.split(y, '.')]
            lan_id = struct.pack("7B",
                                 lan_id[0], lan_id[1], lan_id[2],
                                 lan_id[3], lan_id[4], lan_id[5], lan_id[6])

        elif x in ('-a', '--area-addr'):
            area_addr = [int(x, 16) for x in string.split(y, '.')]

            # this is grim, but that's not important right now...
            area_addr_str = ""
            for i in range(len(area_addr)):
                area_addr_str = struct.pack("%ds B" % len(area_addr_str),
                                            area_addr_str, area_addr[i])
            area_addr = area_addr_str

        elif x in ('-z', '--file-size'):
            file_sz = max(string.atof(y), mrtd.MIN_FILE_SZ)

        elif x in ('-i', '--ip-addr'):
            src_ip = str2id(y)

        else:
            usage()

    #---------------------------------------------------------------------------

    if not area_addr:
        usage()

    isis = Isis(Isis._dev_str, area_addr, src_id, lan_id, src_ip)
    isis._mrtd = mrtd.Mrtd(file_pfx, "w+b", file_sz, mrtd_type, isis)
    if VERBOSE > 1:
        print(repr(isis))

    try:
        timeout = Isis._holdtimer
        while 1: # main loop

            before  = time.time()
            rfds, _, _ = select.select([isis._sock], [], [], timeout)
            after   = time.time()
            elapsed = after - before

            if rfds != []:
                # need to rx pkt(s)
                rv = isis.parseMsg(VERBOSE, 0)

            else:
                # need to tx pkt(s) of some sort
                timeout = Isis._holdtimer
                for mac in list(isis._adjs.keys()):
                    for a in list(isis._adjs[mac].keys()):
                        adj = isis._adjs[mac][a]
                        adj._rtx_at = adj._rtx_at - elapsed
                        if adj._rtx_at <= RETX_THRESH:
                            isis.sendMsg(adj._tx_ish, VERBOSE, 0)
                            adj._rtx_at = adj._holdtimer
                        timeout = min(timeout, adj._rtx_at-RETX_THRESH)

    except (KeyboardInterrupt):
        isis.close()
        sys.exit(1)

################################################################################
################################################################################
