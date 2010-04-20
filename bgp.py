#! /usr/bin/env python2

##     PyRT: Python Routeing Toolkit

##     BGP module: provides the BGP listener and BGP PDU parsers

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

#
# $Id: bgp.py,v 1.22 2002/05/06 11:35:06 mort Exp $
#

import struct, socket, sys, math, getopt, string, os.path, time
from mutils import *

#-------------------------------------------------------------------------------

INDENT          = "    "
VERSION         = "1.0"

RCV_BUF_SZ      = 8192
BGP_LISTEN_PORT = 179
BGP_HDR_LEN     = 19
BGP_MARKER      = struct.pack(">LLLL",
                              0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff)
BGP_MARKER_LEN  = len(BGP_MARKER)

TABLE_DUMP_ENTRY_HDR_LEN = 18

################################################################################

DLIST = []

AFI_TYPES = { 1L: "IP",
              2L: "IP6",
              }
DLIST = DLIST + [AFI_TYPES]

SAFI_TYPES = { 1L: "UNICAST",
               2L: "MULTICAST",
               }
DLIST = DLIST + [SAFI_TYPES]

MSG_TYPES = { 1L: "OPEN",
              2L: "UPDATE", 
              3L: "NOTIFICATION",
              4L: "KEEPALIVE",
              5L: "ROUTE_REFRESH",
              6L: "TABLE_DUMP_ENTRY",
              }
DLIST = DLIST + [MSG_TYPES]

# NB. PAs below actually attribute numbers; only type codes 1-10, 14, 15 valid

PATH_ATTRIBUTES = { 1L:  "ORIGIN",
                    2L:  "AS_PATH",
                    3L:  "NEXT_HOP",
                    4L:  "MULTI_EXIT_DISCRIMINATOR",
                    5L:  "LOC_PREF",
                    6L:  "ATOMIC_AGGR",
                    7L:  "AGGREGATOR",
                    8L:  "COMMUNITY",
                    9L:  "ORIGINATOR_ID",
                    10L: "CLUSTER_LIST",
                    # DPA unused (only ever made draft)
                    11L: "DPA",                         
                    12L: "ADVERTISER",
                    # RCID_PATH never sent to border routers
                    13L: "RCID_PATH/CLUSTER_ID", 
                    14L: "MP_REACH_NLRI",
                    15L: "MP_UNREACH_NLRI",
                    16L: "EXT_COMMUNITIES",
                    }
DLIST = DLIST + [PATH_ATTRIBUTES]

OPT_PARAMS = { 1L: "AUTHENTICATION",
               2L: "CAPABILITY"
               }
DLIST = DLIST + [OPT_PARAMS]

CAP_CODES = { 0L: "UNDEF",
              1L: "MULTIPROTOCOL_EXT",
              2L: "ROUTE_REFRESH",
              
              # 128+ are reserved for vendor-specific applications
              128L: "ROUTE_REFRESH_Z",
              }
DLIST = DLIST + [CAP_CODES]

NLRI_SRC = { 0L: "IGP",
             1L: "EGP",
             2L: "INCOMPLETE"
             }
DLIST = DLIST + [NLRI_SRC]

AS_PATH_SEG_TYPES = { 1L: "SET",
                      2L: "SEQUENCE",
                      3L: "CONFED_SET",
                      4L: "CONFED_SEQUENCE"
                      }
DLIST = DLIST + [AS_PATH_SEG_TYPES]

for d in DLIST: 
    for k in d.keys():
        d[ d[k] ] = k

#-------------------------------------------------------------------------------

# index via [code][subcode]
NOTIFY_STRINGS = [
    [ "message header error",
      [ "connection not synchronized",
        "bad message length",
        "bad message type"
        ]],

    [ "OPEN message error",
      [ "unsupported version number",
        "bad peer AS",
        "bad BGP identifier",
        "unsuported optional parameter",
        "authentication failure",
        "unacceptable hold timer",
        "unsupported capability"
        ]],

    [ "UPDATE message error",
      [ "malformed attribute list",
        "unrecognized well-known attribute",
        "missing well-known attribute",
        "attribute flags error",
        "attribute length error",
        "invalid ORIGIN attribute"
        "AS routing loop",
        "invalid NEXT-HOP attribute",
        "optional attribute error",
        "invalid network field",
        "malformed AS-PATH"
        ]],

    [ "Hold Timer expired",
      [ ""]],

    [ "Finite State Machine error",
      [ ""]],

    [ "Cease",
      [ "maximum number of prefixes reached",
        "administratively shutdown",
        "peer unconfigured",            
        "administratively reset",
        "connection rejected",
        "other configuration change" ]]
    ]

################################################################################

def parseBgpPdu(msg_type, msg_len, msg, verbose=1, level=0):
    
    msg     = msg[BGP_HDR_LEN:]
    msg_len = msg_len - BGP_HDR_LEN
    if   msg_type == MSG_TYPES["OPEN"]:
        rv = parseOpen(msg_len, msg, verbose, level)

    elif msg_type == MSG_TYPES["UPDATE"]:
        rv = parseUpdate(msg_len, msg, verbose, level)
        
    elif msg_type == MSG_TYPES["NOTIFICATION"]:
        rv = parseNotify(msg_len, msg, verbose, level)
        
    elif msg_type == MSG_TYPES["KEEPALIVE"]:
        rv = parseKeepalive(msg_len, msg, verbose, level)
        
    elif msg_type == MSG_TYPES["ROUTE_REFRESH"]:
        rv = parseRouteRefresh(msg_len, msg, verbose, level)

    else:
        rv = {"T": None, "L": 0, "V": None}
        if verbose > 0:
            print level*INDENT + "[ *** UNKNOWN MESSAGE TYPE *** ]"

    return rv
            
#-------------------------------------------------------------------------------

def parseOpen(msg_len, msg, verbose=1, level=0):

    rv = {"T": MSG_TYPES["OPEN"],
          "L": msg_len,
          "V": {}
          }

    if verbose > 1:
        print prtbin(level*INDENT, msg[:msg_len])

    version, as, holdtime, bgp_id = struct.unpack(">BHHL", msg[0:9])

    if verbose > 0:
        print level*INDENT +\
              "Open (len=%d):" % (msg_len+BGP_HDR_LEN, )
        print (level+1)*INDENT +\
              "version: %d, src AS: %d, holdtime: %d, BGP id: %s" %\
              (version, as, holdtime, id2str(bgp_id))

    opts = parseBgpOpts(msg[9:msg_len], verbose, level+1)

    rv["V"] = {"VER":  version,
               "AS":   as,
               "HT":   holdtime,
               "ID":   bgp_id,
               "OPTS": opts
               }
    return rv

#-------------------------------------------------------------------------------

def parseBgpOpts(opts, verbose=1, level=0):

    rv = []

    opts_len = struct.unpack("B", opts[0])
    if verbose > 1:
        print prtbin(level*INDENT, opts[0])
        
    if verbose > 0:
        print level*INDENT + "optional params. len=%d" % opts_len

    opts = opts[1:]
    while len(opts) > 0:

        opt_type, opt_len = struct.unpack("BB", opts[0:2])
        trv = { "T": opt_type,
                "L": opt_len,
                "V": {}
                }
           
        if verbose > 1:
            print prtbin(level*INDENT, opts[0:2+opt_len])
        if verbose > 0:
            print level*INDENT +\
                  "option type: %s, len=%d" % (OPT_PARAMS[opt_type], opt_len)

        opts = opts[2:]

        if opt_type == OPT_PARAMS["CAPABILITY"]:

            level = level + 1            
            cap_code, cap_len = struct.unpack("BB", opts[0:2])
            
            trv["V"] = { "T": cap_code,
                         "L": cap_len,
                         "V": {}
                         }

            if verbose > 0:
                if verbose > 1:
                    print prtbin(level*INDENT, opts[0:2+cap_len])
                print level*INDENT +\
                      "capability:", CAP_CODES[cap_code], "len=" + `cap_len`

                if verbose > 1:
                    print prtbin(level*INDENT, opts[2:2+cap_len])
                if cap_code == CAP_CODES["MULTIPROTOCOL_EXT"]:
                    afi, safi = struct.unpack(">HH", opts[2:2+cap_len])
                    if verbose > 1:
                        print level*INDENT +\
                              "afi:", AFI_TYPES[afi], "safi:", SAFI_TYPES[safi]

                    trv["V"]["V"] = { "AFI": afi, "SAFI": safi }

                elif cap_code == CAP_CODES["ROUTE_REFRESH"]:
                    pass

                elif cap_code == CAP_CODES["ROUTE_REFRESH_Z"]:
                    pass
                    
                else:
                    print level*INDENT +\
                          "[ *** UNKNOWN CAPABILITY CODE: %d *** ]" % cap_code
            level = level - 1

        else:
            if verbose > 0:
                print level*INDENT +\
                      "[ *** UNKNOWN OPTIONAL PARAMETER: %d *** ]" % opt_type

        rv.append(trv)
        opts = opts[opt_len:]

    return rv

#-------------------------------------------------------------------------------

def parseUpdate(msg_len, msg, verbose=1, level=0):

    rv = {"T": MSG_TYPES["UPDATE"],
          "L": msg_len,
          "V": { "UNFEASIBLE": [], "PATH_ATTRS": {}, "FEASIBLE": [] }
          }
        
    curp = 0

    # "BGP4: Inter-domain routing in the Internet" John W. Stewart III.
    # Unfeasible (withdrawn) routes are a sequence of (len, pfx) pairs, where
    # len is the length of the prefix in _bits_, and pfx is the prefix, padded
    # to a whole number of octets.  All such padding must be ignored.

    (unfeasible_len, ) = struct.unpack(">H", msg[curp:curp+2])
    unfeasible_pfxs = "\n"
    if verbose > 1:
        unfeasible_pfxs = unfeasible_pfxs +\
                          prtbin((level+1)*INDENT, msg[0:2+unfeasible_len])
    unfeasible_pfxs = unfeasible_pfxs +\
                      "\n" + (level+1)*INDENT + "UNFEASIBLE ROUTES:\n"
        
    curp = curp + 2
    endp = curp + unfeasible_len

    rn   = 0
    while curp != endp:

        rn = rn + 1

        (plen, )    = struct.unpack("B", msg[curp])
        plen_octets = int(math.ceil(plen/8.0))
        curp = curp + 1

        (pfx,) = struct.unpack("%ds" % plen_octets, msg[curp:curp+plen_octets])
        unfeasible_pfxs = unfeasible_pfxs + (level+2)*INDENT +\
                           "%d: %s\n" % (rn, pfx2str(pfx, plen))

        rv["V"]["UNFEASIBLE"].append((pfx,plen))
        curp = curp + plen_octets

    # "BGP4: Inter-domain routing in the Internet" John W. Stewart III,
    # pp.37--40.  (T,L,V) encoded.  TYPE is 2 octets, split into FLAGS and
    # TYPECODE.  LENGTH is 1 or 2 octets based on EXTENDED-LENGTH field in FLAGS
    # and is in octets (bottom p.39).  VALUE is parsed as given by TYPE-CODE,
    # cf. section 2.4

    (path_attr_len, ) = struct.unpack(">H", msg[curp:curp+2])
    path_attrs = ""
    if verbose > 1:
        path_attrs = path_attrs +\
                     prtbin((level+1)*INDENT, msg[curp:curp+2+path_attr_len])
    path_attrs = path_attrs + "\n" + (level+1)*INDENT + "PATH ATTRIBUTES:\n"

    curp = curp + 2
    endp = curp + path_attr_len

    rn   = 0
    while curp != endp:

        rn = rn + 1

        aflags, atype = struct.unpack("BB", msg[curp:curp+2])
        curp = curp + 2

        flg_optional   = (aflags & (1<<7)) >> 7
        flg_transitive = (aflags & (1<<6)) >> 6
        flg_partial    = (aflags & (1<<5)) >> 5
        flg_extlen     = (aflags & (1<<4)) >> 4

        # XXX this is a bit grim, but it seems that there's no way to
        # do this more nicely :-(

        if flg_extlen+1 == 1:
            (alen, ) = struct.unpack("B", msg[curp:curp+flg_extlen+1])
        elif flg_extlen+1 == 2:
            (alen, ) = struct.unpack(">H", msg[curp:curp+flg_extlen+1])
        else:
            error('flg_extlen was neither 0 nor 1 :-(')
            sys.exit(1)

        curp  = curp + flg_extlen+1
        adata = msg[curp:curp+alen]

        (pa_str, pa_trv) = parseBgpAttr(atype, alen, adata, verbose, level+2)
        path_attrs = path_attrs + pa_str
        
        flgs_str = "%s %s %s %s" %\
                   ("optional"*flg_optional, "transitive"*flg_transitive,
                    "partial"*flg_partial,   "extended length"*flg_extlen)
	flgs_str = string.strip(flgs_str)
	flgs_str = " [ %s ]\n" % flgs_str
        path_attrs = path_attrs + flgs_str
        pa_trv["FLAGS"] = {"optional":   flg_optional,
                           "transitive": flg_transitive,
                           "partial":    flg_partial,
                           "extlen":     flg_extlen,
                           }
        rv["V"]["PATH_ATTRS"][ pa_trv["T"] ] = pa_trv

        curp = curp + alen

    # NLRI information: the prefixes to which path attributes apply
    # <len(bits),pfx>*

    nlri_pfxs = (level+1)*INDENT + "FEASIBLE ROUTES:\n"
    endp = curp + len(msg[curp:])
    rn   = 0

    while curp < endp:

        rn = rn + 1

        (plen, )    = struct.unpack("B", msg[curp])
        plen_octets = int(math.ceil(plen/8.0))
        curp = curp + 1

        if verbose > 1:
            nlri_pfxs = nlri_pfxs + prtbin((level+2)*INDENT,
                                           msg[curp-1:curp+plen_octets]) + "\n"

        (pfx,) = struct.unpack("%ds" % len(msg[curp:curp+plen_octets]),
                               msg[curp:curp+plen_octets])

        nlri_pfxs = nlri_pfxs +\
                    (level+2)*INDENT + "%d: %s %s\n" %\
                    (rn, pfx2str(pfx, plen),
                     (len(msg[curp:curp+plen_octets]) != plen_octets)*
                     '[ *** bogus NLRI field: plen_octets did not match *** ]')

        rv["V"]["FEASIBLE"].append((pfx,plen))
        curp = curp + plen_octets

    if verbose > 0:
        print level*INDENT +\
              "Update (len=%d): unfeasible_len=%d path_attr_len=%d%s%s%s" %\
              (msg_len+BGP_HDR_LEN, unfeasible_len, path_attr_len,
               unfeasible_pfxs, path_attrs, nlri_pfxs)

    return rv
            
#-------------------------------------------------------------------------------

def parseBgpAttr(atype, alen, adata, verbose=1, level=0):

    rv = {"T": atype,
          "L": alen,
          "V": None
          }

    if len(adata) == 0:
        ret = level*INDENT + PATH_ATTRIBUTES[atype] + ": null"
        return (ret, rv)
    
    if atype in PATH_ATTRIBUTES.keys():

        if atype == PATH_ATTRIBUTES["ORIGIN"]:
            (nlri_src, ) = struct.unpack("B", adata)

            ret = level*INDENT + "ORIGIN: %s" % NLRI_SRC[nlri_src]
            rv["V"] = nlri_src

        elif atype == PATH_ATTRIBUTES["AS_PATH"]:
            
            ret     = level*INDENT + "AS_PATH: " 
            rv["V"] = []

            while adata:
                asp_t, asp_l = struct.unpack("BB", adata[0:2])
                rv_cpt = { "T": asp_t, "L": asp_l, "V": [] }

                asp_v = adata[2:2+2*asp_l]
                if asp_v:
                    path = struct.unpack(">%dH" % asp_l, asp_v)
                    if(asp_t == AS_PATH_SEG_TYPES["SET"] or
                       asp_t == AS_PATH_SEG_TYPES["CONFED_SET"]):
                        
                        ret = ret + '(%s){ ' % AS_PATH_SEG_TYPES[asp_t]
                        for as in path:
                            ret = ret + "%d, " % as
                            rv_cpt["V"].append(as)
                        ret = ret + '}'

                    elif(asp_t == AS_PATH_SEG_TYPES["SEQUENCE"] or
                         asp_t == AS_PATH_SEG_TYPES["CONFED_SEQUENCE"]):

                        ret = ret + '(%s)[ ' % AS_PATH_SEG_TYPES[asp_t]
                        for as in path:
                            ret = ret + "<- %d " % as
                            rv_cpt["V"].append(as)
                        ret = ret + ']'
                        
                rv["V"].append(rv_cpt)
                adata = adata[2+(asp_l*2):]
                        
        elif atype == PATH_ATTRIBUTES["NEXT_HOP"]:
            (nh, ) = struct.unpack(">L", adata)
            ret    = level*INDENT + "NEXT_HOP: " + id2str(nh)
            rv["V"] = nh

        elif atype == PATH_ATTRIBUTES["MULTI_EXIT_DISCRIMINATOR"]:
            (med, ) = struct.unpack(">L", adata)
            ret     = level*INDENT + "MED: " + `med`
            rv["V"] = med
            
        elif atype == PATH_ATTRIBUTES["LOC_PREF"]:
            (lp, ) = struct.unpack(">L", adata)
            ret    = level*INDENT + "LOC_PREF: " + `lp`
            rv["V"] = lp

        # ATOMIC_AGGREGATOR hit by null check at start...
        elif atype == PATH_ATTRIBUTES["AGGREGATOR"]:
            (as, ip) = struct.unpack(">H L", adata)
            ret = level*INDENT +\
                  "AGGREGATOR: formed by AS %d, router %s" % (as, id2str(ip))
            rv["V"] = (as, ip)

        elif atype == PATH_ATTRIBUTES["COMMUNITY"]:

            ret = ""
            rv["V"] = []
            for i in range(alen/4):
                x,y = struct.unpack(">HH", adata[i*4:(i+1)*4])
                ret = ret + level*INDENT + "COMMUNITY %d: %d:%d\n" % (i+1, x, y)
                rv["V"].append(adata[i*4:(i+1)*4])
            ret = ret[:-1]

        elif atype == PATH_ATTRIBUTES["ORIGINATOR_ID"]:

            (id,) = struct.unpack(">L", adata)
            ret = level*INDENT + "ORIGINATOR_ID: %s" % id2str(id)
            rv["V"] = id

        elif atype == PATH_ATTRIBUTES["CLUSTER_LIST"]:

            # These are 'defined' in RFC 1966 (route reflectors).  Or so they
            # should be.  In fact, the RFC talks complete bollocks
            # re. CLUSTER_LIST -- it defines nothing and appears to be just
            # plain wrong.  However, as usual, there is magic: from Cisco, we
            # see http://www.cisco.com/networkers/nw99_pres/309.pdf, which says
            # CLUSTER_LIST is "...just a list of ORIGINATOR_IDs...".  So there
            # we go.  I have _no idea_ what the encoding of the originator ids
            # is here -- I assume the standard ">L" for convenience.
            
            ret = level*INDENT + "CLUSTER_LIST"
            rv["V"] = []
            for i in range(alen/4):
                (id,) = struct.unpack(">L", adata[:4])
                ret = ret + ": %s" % id2str(id)
                rv["V"].append(id)

        else:
            ret = level*INDENT + "[ *** %s *** ]" % PATH_ATTRIBUTES[atype]

    else:
        ret = level*INDENT +\
              "[ *** UNKNOWN BGP path attribute: %d *** ]" % atype

    return (ret, rv)
        
#-------------------------------------------------------------------------------

def parseNotify(msg_len, msg, verbose=1, level=0):

    rv = {"T": MSG_TYPES["NOTIFICATION"],
          "L": msg_len,
          "V": None
          }

    if verbose > 1:
        print prtbin(level*INDENT, msg[:msg_len])

    code, subcode, data = struct.unpack("BB %ds" % (msg_len-2, ), msg)
    code    = code - 1
    subcode = subcode - 1

    if verbose > 0:
        print level*INDENT + "Notification (len=%d): %s : %s" %\
              (msg_len,
               NOTIFY_STRINGS[code][0], NOTIFY_STRINGS[code][1][subcode])

    ## XXX data?

    return rv

#-------------------------------------------------------------------------------

def parseKeepalive(msg_len, msg, verbose=1, level=0):

    rv = {"T": MSG_TYPES["KEEPALIVE"],
          "L": msg_len,
          "V": None
          }
    
    if verbose > 1:
        print prtbin(level*INDENT, msg)

    if verbose > 0:
        print level*INDENT + "Keepalive (len=%d)\n" % (msg_len+BGP_HDR_LEN, )

    return rv

#-------------------------------------------------------------------------------

def parseRouteRefresh(msg_len, msg, verbose=1, level=0):

    rv = {"T": MSG_TYPES["ROUTE_REFRESH"],
          "L": msg_len,
          "V": None
          }
          
    if verbose > 1:
        print prtbin(level*INDENT, msg)

    if verbose > 0:
        print level*INDENT +  "RouteRefresh (len=%d)" % (msg_len+BGP_HDR_LEN, )

    return rv

#-------------------------------------------------------------------------------

def parseTableEntry(length, entries, verbose=1, level=0):

    rv = {"T": MSG_TYPES["TABLE_DUMP_ENTRY"],
          "L": 0,
          "V": {}
          }

    hfmt = ">LBBLLHH"
    hfmt_l = struct.calcsize(hfmt)

    pfx, plen, status, uptime, peer_addr, peer_as, elen =\
         struct.unpack(hfmt, entries[:hfmt_l])
    
    rv["V"]["PREFIX"]  = (struct.pack(">L", pfx), plen)
    rv["V"]["STATUS"]  = status
    rv["V"]["UPTIME"]  = uptime
    rv["V"]["PEER_IP"] = peer_addr
    rv["V"]["PEER_AS"] = peer_as
    
    if verbose:
        print level*INDENT +\
              "prefix: %s/%d, peer IP: %s, peer AS: %d" %\
              (id2str(pfx), plen, id2str(peer_addr), peer_as)
        print level*INDENT + "updated: '%s'" % (time.ctime(uptime),)

    entries = entries[TABLE_DUMP_ENTRY_HDR_LEN:]
    rv["V"]["ATTRS"] = entries

    # XXX This should reuse part of bgp.parseUpdate() -- need to further
    # separate out the path attr. parsing.  Cut'n'paste for now since I'm in
    # a hurry.

    if verbose:
        print level*INDENT + 'PATH ATTRIBUTES: len=%d' % elen

    rv["L"] = TABLE_DUMP_ENTRY_HDR_LEN + elen
    while elen:
        if verbose > 1:
            print prthex(level*INDENT + 'flags/type:', entries[:2])

        aflags, atype = struct.unpack(">BB", entries[0:2])

        flg_optional   = (aflags & (1<<7)) >> 7
        flg_transitive = (aflags & (1<<6)) >> 6
        flg_partial    = (aflags & (1<<5)) >> 5
        flg_extlen     = (aflags & (1<<4)) >> 4

        flgs_str = "%s %s %s %s" %\
                   ("optional"*flg_optional, "transitive"*flg_transitive,
                    "partial"*flg_partial,   "extended length"*flg_extlen)
        flgs_str = string.strip(flgs_str)
        flgs_str = " [ %s ]" % flgs_str

        if verbose > 1:
            print prthex(level*INDENT + 'length:',
                         entries[2+flg_extlen:2+flg_extlen+1])
        (alen, ) = struct.unpack("%dB" % (flg_extlen+1),
                                 entries[2:2+flg_extlen+1])
        (adata,) = struct.unpack("%ds" % alen,
                                 entries[2+flg_extlen+1:2+flg_extlen+1+alen])

        if verbose > 1:
            print prthex(level*INDENT +'value:',
                         entries[2+flg_extlen+1:2+flg_extlen+1+alen])

        (astr, arv) = parseBgpAttr(atype, alen, adata, verbose, level+1)

        rv["V"][atype] = arv

        if verbose:
            print astr + flgs_str
        entries = entries[2+flg_extlen+1+alen:]
        elen    = elen - (2+flg_extlen+1+alen)

    if verbose: print
    return rv

################################################################################

class Bgp:

    _version = 4

    #---------------------------------------------------------------------------


    def __init__(self, loc_name, as, rem_name, port, holdtime):

        self._bgp_id_str  = loc_name
        self._bgp_id_addr = socket.gethostbyname(loc_name)
        self._bgp_id      = str2id(self._bgp_id_addr)
        self._bgp_as      = as

        self._bgp_peer_str  = rem_name
        self._bgp_peer_addr = socket.gethostbyname(rem_name)
        self._bgp_peer_id   = str2id(self._bgp_peer_addr)
        self._bgp_peer_prt  = port
        self._bgp_peer_as   = 0

        self._holdtime = holdtime

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((self._bgp_id_str, 0))
        self._sock.connect((self._bgp_peer_str, self._bgp_peer_prt))

        self._rcvd = ""
        self._mrt  = None
        
    def __repr__(self):
            
        ret = """Passive BGP speaker version %s:
        id: %s [%s] (%#0x), AS: %d
        peer: %s:%d [%s] (%#0x), AS: %d
        holdtime: %d\n""" %\
            (VERSION,
             self._bgp_id_str, self._bgp_id_addr, self._bgp_id, self._bgp_as,
             self._bgp_peer_str, self._bgp_peer_prt, self._bgp_peer_addr,
             self._bgp_peer_id, self._bgp_peer_as, self._holdtime)

        return ret

    def close(self):
        # XXX RMM XXX should possibly be a __del__() method?
        self._sock.close()
        self._mrt.close()

    #---------------------------------------------------------------------------

    def recvMsg(self, verbose=1, level=0):

        while 1:
        
            if len(self._rcvd) < BGP_MARKER_LEN+3:
                self._rcvd = self._rcvd + self._sock.recv(RCV_BUF_SZ)
                continue

            ## guaranteed to have a BGP-msg-header-worth of data in buffer
            
            msg_start = string.find(self._rcvd, BGP_MARKER)
            if msg_start < 0:
                # no marker in buffer -- fill buffer and continue
                self._rcvd = self._rcvd + self._sock.recv(RCV_BUF_SZ)
                continue
            
            elif msg_start > 0:
                # marker not at buffer start -- dump skipped data to debug
                sys.stderr.write(prtbin("", self._rcvd[:msg_start]) + "\n---\n")
                sys.stderr.flush()

            ## msg_start is now at the start of a message

            msg_len, msg_type =\
                     struct.unpack(">HB",
                                   self._rcvd[msg_start+BGP_MARKER_LEN :
                                              msg_start+BGP_MARKER_LEN+3])
            break

        ## message may not be completely received...

        while msg_len > len(self._rcvd):
            self._rcvd = self._rcvd + self._sock.recv(RCV_BUF_SZ)

        msg_end = msg_start + msg_len

        ## guaranteed to have the entire message in [msg_start..msg_end]

        msg        = self._rcvd[msg_start:msg_end]                        
        self._rcvd = self._rcvd[msg_end:]

        ## have now advanced buffer past current message; current
        ## message available in msg

        if verbose > 2:
            print "recvMsg: msg: type=%s (%d) len=%d%s" %\
                  (MSG_TYPES[msg_type], msg_type, msg_len,
                   prtbin(level*INDENT, msg))
            
        return msg_type, msg_len, msg
        
    def sendMsg(self, msg_type, msg_len, msg, verbose=1, level=0):

        fmt = ">LLLLH B %ds" % msg_len
        pkt = struct.pack(fmt,
                          0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 
                          msg_len+BGP_HDR_LEN, msg_type, msg)

        if DUMP_MRTD == 1:
            self._mrt.writeBgp4pyMsg(msg_type, len(pkt), pkt)
        elif DUMP_MRTD == 2:
            self._mrt.writeBgpMsg(msg_type, len(pkt), pkt)
        elif DUMP_MRTD == 3:
            self._mrt.writeBgp4mpMsg(msg_type, len(pkt), pkt)

        if verbose > 2:
            print "%ssendMsg: type=%s (%d), len=%d%s" %\
                  (level*INDENT, MSG_TYPES[msg_type], msg_type,
                   struct.calcsize(fmt), prtbin((level+1)*INDENT, pkt))

        self._sock.send(pkt)

    def parseMsg(self, verbose=1, level=0):

        msg_type, msg_len, msg = self.recvMsg()

        if DUMP_MRTD == 1:
            self._mrt.writeBgp4pyMsg(msg_type, msg_len, msg)
        elif DUMP_MRTD == 2:
            self._mrt.writeBgpMsg(msg_type, msg_len, msg)
        elif DUMP_MRTD == 3:
            self._mrt.writeBgp4mpMsg(msg_type, msg_len, msg)

        if verbose > 2:
            print "%sparseMsg: type=%s (%d) len=%d%s" %\
                  (level*INDENT, MSG_TYPES[msg_type], msg_type,
                   msg_len-BGP_HDR_LEN,
                   prtbin((level+1)*INDENT, msg[BGP_HDR_LEN:]))

        rv = parseBgpPdu(msg_type, msg_len, msg, verbose, level)

        return rv # msg_type, msg_len, msg

    #---------------------------------------------------------------------------
        
    def sendOpen(self, verbose=1, level=0):

        print `type(self._bgp_id)`, `self._bgp_id`
        
        fmt = ">BHHLB"
        msg = struct.pack(fmt, Bgp._version,
                          self._bgp_as, self._holdtime, self._bgp_id, 0)

        if verbose > 2:
            print "%ssendOpen: len=%d%s" %\
                  (level*INDENT, struct.calcsize(fmt),
                   prtbin((level+1)*INDENT, msg))

        parseOpen(len(msg), msg, verbose, level)
        self.sendMsg(MSG_TYPES["OPEN"],
                     struct.calcsize(fmt), msg, verbose, level)

    def sendKeepalive(self, verbose=1, level=0):

        fmt = ""
        msg = ""
        if verbose > 2:
            print "sendKeepalive: len=%d%s" %\
                  (struct.calcsize(fmt), prtbin(level*INDENT, msg))

        parseKeepalive(len(msg), msg, verbose, level)
        self.sendMsg(MSG_TYPES["KEEPALIVE"], 0, msg, verbose, level)

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
    loc_name  = None
    rem_name  = None
    as        = None
    port      = BGP_LISTEN_PORT
    holdtime  = 0

    #---------------------------------------------------------------------------

    def usage():

        print """Usage: %s [ options ] ([*] options required):
        -h|--help     : Help
        -q|--quiet    : Be quiet
        -v|--verbose  : Be verbose
        -V|--VERBOSE  : Be very verbose
        
        -f|--file     : Set file prefix for MRTd dump [def: %s]
        -y|--dump-4py : Dump MRTd::PROTOCOL_BGP4PY format [default]
        -d|--dump     : Dump MRTd::PROTOCOL_BGP format
        -m|--dump-4mp : Dump MRTd::PROTOCOL_BGP4MP format

        -p|--peer     : [*] BGP peer address/name
        -a|--as       : [*] Local AS number
        -l|--local    : Address/name for local bind
        -t|--port     : BGP peer listening port [def: %d]
        -z|--size     : Size of output file(s) [min: %d]""" %\
            (os.path.basename(sys.argv[0]), mrtd.DEFAULT_FILE,
             BGP_LISTEN_PORT, mrtd.MIN_FILE_SZ)
        sys.exit(0)

    #---------------------------------------------------------------------------
    
    if len(sys.argv) < 2:
        usage()
        
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hqvVydmp:a:o:t:l:f:z:",
                                   ("help", "quiet", "verbose", "VERBOSE",
                                    "dump-4py", "dump", "dump-4mp",
                                    "file-pfx=", "peer=", "as=", "holdtime=",
                                    "port=", "local=", "size=" ))
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

        elif x in ('-y', '--dump-4py'):
            DUMP_MRTD = 1
            mrtd_type = mrtd.MSG_TYPES["PROTOCOL_BGP4PY"]
            
        elif x in ('-d', '--dump'):
            DUMP_MRTD = 2
            mrtd_type = mrtd.MSG_TYPES["PROTOCOL_BGP"]
            
        elif x in ('-m', '--dump-4mp'):
            DUMP_MRTD = 3
            mrtd_type = mrtd.MSG_TYPES["PROTOCOL_BGP4MP"]
            
        elif x in ('-p', '--peer'):
            rem_name = y
            
        elif x in ('-a', '--as'):
            as = string.atoi(y)
            
        elif x in ('-o', '--holdtime'):
            holdtime = string.atoi(y)
            
        elif x in ('-t', '--port'):
            port = string.atoi(y)
            
        elif x in ('-l', '--local'):
            loc_name = y

        elif x in ('-f', '--file-pfx'):
            file_pfx = y

        elif x in ('-z', '--file-size'):
            file_sz = max(string.atof(y), mrtd.MIN_FILE_SZ)

        else:
            usage()
    
    if not (rem_name and as):
        usage()

    if not loc_name:
        loc_name = socket.gethostname()

    #---------------------------------------------------------------------------

    bgp      = Bgp(loc_name, as, rem_name, port, holdtime)
    bgp._mrt = mrtd.Mrtd(file_pfx, "w+b", file_sz, mrtd_type, bgp)
        
    if VERBOSE > 0:
        print `bgp`
    
    try:

        # the wafeur-est thin state machine you ever did see :-)
        bgp.sendOpen(VERBOSE, 0)
        rv = bgp.parseMsg(VERBOSE, 0)
        bgp._bgp_peer_as = rv["V"]["AS"]
        bgp.sendKeepalive(VERBOSE, 0)

        while 1:
            msg = bgp.parseMsg(VERBOSE, 0)

    except (KeyboardInterrupt):
        bgp.close()
        sys.exit(1)
        
    #---------------------------------------------------------------------------

################################################################################
################################################################################
