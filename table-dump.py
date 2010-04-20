#! /usr/bin/env python

##     PyRT: Python Routeing Toolkit

##     Manipulates MRTd dumps, splicing one or more dumps together in
##     time order, and outputting the result given start/end times,
##     and given a certain 'chunk' size.

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
# $Id: table-dump.py,v 1.3 2002/02/26 01:57:03 mort Exp $
#

import time, getopt, sys, string, os, pprint
import mrtd, bgp
from mutils import *

VIEW_NO      = 0x00
STATUS       = 0x01
MINS_TO_SECS = 60

################################################################################

def processEntry(rv):

    def mkStr(attr, aval):
    
        flags = 0
        if aval["FLAGS"]['optional']:
            flags = flags | (1<<7)
        if aval["FLAGS"]['transitive']:
            flags = flags | (1<<6)
        if aval["FLAGS"]['partial']:
            flags = flags | (1<<5)
        if aval["FLAGS"]['extlen']:
            flags = flags | (1<<4)

        rflgs = struct.pack('BB', flags & 0xff, attr & 0xff)
        if   attr == bgp.PATH_ATTRIBUTES["ORIGIN"]:
            rval = struct.pack('B', aval["V"])
                        
        elif attr == bgp.PATH_ATTRIBUTES["AS_PATH"]:
            if aval["V"] != None:
                for pseg in aval["V"]:
                    tl = struct.pack('BB', pseg["T"], pseg["L"])
                    val = ""
                    for v in pseg["V"]:
                        val = struct.pack('>%dsH' % len(val), val, v)
                rval = struct.pack('%ds%ds' % (len(tl), len(val)), tl, val)
            else:
                rval = struct.pack('BB',
                                   bgp.AS_PATH_SEG_TYPES['SEQUENCE'], 0)

        elif attr == bgp.PATH_ATTRIBUTES["NEXT_HOP"]:
            rval = struct.pack('>L', aval["V"])

        elif attr == bgp.PATH_ATTRIBUTES["MULTI_EXIT_DISCRIMINATOR"]:
            rval = struct.pack('>L', aval["V"])
            
        elif attr == bgp.PATH_ATTRIBUTES["LOC_PREF"]:
            rval = struct.pack('>L', aval["V"])

        elif attr == bgp.PATH_ATTRIBUTES["ATOMIC_AGGR"]:
            rval = ""

        elif attr == bgp.PATH_ATTRIBUTES["AGGREGATOR"]:
            rval = struct.pack(">HL", aval["V"][0], aval["V"][1])

        elif attr == bgp.PATH_ATTRIBUTES["COMMUNITY"]:
            rval = ""
            for v in aval["V"]:
                rval = struct.pack('>%ds4s' % len(rval), rval, v)

        elif attr == bgp.PATH_ATTRIBUTES["ORIGINATOR_ID"]:
            rval = struct.pack('>L', aval["V"])

        elif attr == bgp.PATH_ATTRIBUTES["CLUSTER_LIST"]:
            rval = ""
            for v in aval["V"]:
                rval = struct.pack('>%dsL' % len(rval), rval, v)

        else:
            print '[ *** Unsupported attribute:', \
                  bgp.PATH_ATTRIBUTES[attr], '*** ]'
            return None

        if aval["FLAGS"]['extlen']:            
            rlen = struct.pack('>H', len(rval) & 0xffff)
        else:
            rlen = struct.pack('>B', len(rval) & 0xff)

        return struct.pack('%ds%ds%ds' % (len(rflgs), len(rlen), len(rval)),
                           rflgs, rlen, rval)

    msg_tm = rv["H"]["TIME"]
    src_as, src_ip = rv["H"]["SRC_AS"], rv["H"]["SRC_IP"]
    ifc, afi = rv["H"]["IFC"], rv["H"]["AFI"]

    for pfx in rv["V"]["V"]["UNFEASIBLE"]:
        del TABLE[pfx]

    astr = ""
    for attr in rv["V"]["V"]["PATH_ATTRS"].keys():
        rstr = mkStr(attr, rv["V"]["V"]["PATH_ATTRS"][attr])
        astr = struct.pack('%ds%ds' % (len(astr), len(rstr)),
                           astr, rstr)

        
    for pfx in rv["V"]["V"]["FEASIBLE"]:
        TABLE[pfx] = {"TIME"   : msg_tm,
                      "PEER_IP": src_ip,
                      "PEER_AS": src_as,
                      "ATTRS"  : astr,
                      }

#-------------------------------------------------------------------------------

def dumpTable():

    now = time.time()
    date_str = time.strftime(".%Y-%m-%d_%H.%M.%S", time.gmtime(LAST_TM))
    of = open(OUTPUT_F + date_str, 'w+b')

    error('dumping...')

    seq_no = 0
    for (pfx, plen) in TABLE.keys():
        attr_len = len(TABLE[(pfx,plen)]['ATTRS'])
        common_hdr = struct.pack('>HH', VIEW_NO, seq_no)
        entry      = struct.pack('>4sBBLLHH%ds' % attr_len,
                                 pfx, plen, STATUS,
                                 TABLE[(pfx,plen)]['TIME'],
                                 TABLE[(pfx,plen)]['PEER_IP'],
                                 TABLE[(pfx,plen)]['PEER_AS'],
                                 attr_len, TABLE[(pfx,plen)]['ATTRS'])
        
        mrt_hdr = struct.pack('>LHHL',
                              now,
                              mrtd.MSG_TYPES['TABLE_DUMP'],
                              mrtd.TABLE_DUMP_SUBTYPES['IP'],
                              attr_len+\
                              mrtd.TABLE_DUMP_HDR_LEN+\
                              bgp.TABLE_DUMP_ENTRY_HDR_LEN)

        of.write('%s%s%s' % (mrt_hdr, common_hdr, entry))
        seq_no = seq_no + 1

    error('[%d] entries...' % len(TABLE.keys()) )

    of.close()

################################################################################

if __name__ == "__main__":

    VERBOSE  = 1
    START_T  = -1
    INTERVAL = -1
    LAST_TM  = -1

    OUTPUT_F = 'bview'
    TABLE_F = None
    TABLE   = {}
    
    #---------------------------------------------------------------------------

    def usage():

        print """Usage: %s [ options ] <filenames>:
        -h|--help       : Help
        -q|--quiet      : Be quiet
        -v|--verbose    : Be verbose

        -f|--file       : Filename prefix for output
        -s|--start-time : Start time of packets of interest [inclusive]
        -i|--interval   : Table dump invterval (minutes)
        -t|--table      : Initial table [def.: none]""" %\
            (os.path.basename(sys.argv[0]),)
        sys.exit(0)
    
    #---------------------------------------------------------------------------

    if len(sys.argv) < 2:
        usage()
        
    try:
        opts, args =\
              getopt.getopt(sys.argv[1:],
                            "hqvf:s:i:t:",
                            ("help", "quiet", "verbose",
                             "file=", "start-time=", "interval=", "table=" ))
    except (getopt.error):
        usage()

    for (x, y) in opts:        
        if x in ('-h', '--help'):
            usage()

        elif x in ('-q', '--quiet'):
            VERBOSE = 0

        elif x in ('-v', '--verbose'):
            VERBOSE = 2

        elif x in ('-f', '--file'):
            OUTPUT_F = y

        elif x in ('-s', '--start-time'):
            START_T = time.mktime(time.strptime(y))

        elif x in ('-i', '--interval'):
            INTERVAL = string.atol(y) * MINS_TO_SECS

        elif x in ('-t', '--table'):
            TABLE_F = y

        else:
            usage()

    filenames = args
    if not filenames:
        usage()

    #---------------------------------------------------------------------------

    NEXT_DUMP = START_T + INTERVAL

    # seed from dump if required here

    if TABLE_F:
        cnt = 0
        error('[ %s ] initializing table...' % TABLE_F)
        try:
            mrt = mrtd.Mrtd(TABLE_F, "rb")
            while 1:
                rv = mrt.parse(mrt.read(), VERBOSE)
                cnt = cnt + 1
                if rv["T"] == mrtd.MSG_TYPES["TABLE_DUMP"]:
                    for v in rv["V"]:
                        pfx = v["V"]["PREFIX"]
                        entry = { "TIME"   : v["V"]["UPTIME"],
                                  "PEER_IP": v["V"]["PEER_IP"],
                                  "PEER_AS": v["V"]["PEER_AS"],
                                  "ATTRS"  : v["V"]["ATTRS"],
                                  }

                        TABLE[pfx] = entry
        except (mrtd.EOFExc):
            error("end of file: %u messages\n" % cnt)
        except (KeyboardInterrupt):
            error("interrupted: %u messages\n" % cnt)
        mrt.close()
        error('done\n')

    print 'init entries:', `len(TABLE.keys())`

    # process UPDATE files
    
    for fn in filenames:
        cnt = 0
        try:
            error('[ %s ] parsing...' % fn)
            mrt = mrtd.Mrtd(fn, "rb")
            while 1:
                msg = mrt.read()
                cnt = cnt + 1
                if (START_T < 0) or (msg[0] >= START_T):
                    rv = mrt.parse(msg, VERBOSE)
                    if ((rv["T"] == mrtd.MSG_TYPES["PROTOCOL_BGP"] and
                         rv["ST"] == mrtd.BGP_SUBTYPES["UPDATE"])
                        or
                        (rv["T"] == mrtd.MSG_TYPES["PROTOCOL_BGP4MP"] and
                         rv["ST"] == mrtd.BGP4MP_SUBTYPES["MESSAGE"] and
                         rv["V"]["T"] == bgp.MSG_TYPES["UPDATE"])
                        or
                        (rv["T"] == mrtd.MSG_TYPES["PROTOCOL_BGP4PY"] and
                         rv["ST"] == mrtd.BGP4MP_SUBTYPES["MESSAGE"] and
                         rv["V"]["T"] == bgp.MSG_TYPES["UPDATE"])
                        ):

                        processEntry(rv)

                        LAST_TM = msg[0]
                        if (LAST_TM > NEXT_DUMP and NEXT_DUMP > START_T):
                            dumpTable()
                            NEXT_DUMP = NEXT_DUMP + INTERVAL

        except (mrtd.EOFExc):
            error("end of file: %u messages..." % cnt)
        except (KeyboardInterrupt):
            error("interrupted: %u messages..." % cnt)
        error('done\n')
        mrt.close()

    # do a final table dump

    dumpTable()
    
    sys.exit(0)

################################################################################
################################################################################
