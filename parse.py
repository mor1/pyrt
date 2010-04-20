#! /usr/bin/env python

##     PyRT: Python Routeing Toolkit

##     Demonstrates how to use MRTd module to parse dumps.

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
# $Id: parse.py,v 1.9 2002/02/06 16:58:46 mort Exp $
#

# Dummy script to demonstrate basics of parsing MRTd dump files.
# Prints all parsed data structures to stdout.

import os, time, struct, getopt, sys, bgp, isis, mrtd, pprint
from mutils import *

################################################################################

if __name__ == "__main__":

    VERBOSE = 1
    START_T = -1
    END_T   = -1

    #---------------------------------------------------------------------------

    def usage():

        print """Usage: %s [ options ] <filenames>:
        -h|--help      : Help
        -v|--verbose   : Be verbose
        -q|--quiet     : Be quiet

        -s|--start-time: Start time of packets of interest [inclusive]
        -t|--end-time  : End time of packets of interest [inclusive]""" %\
            (os.path.basename(sys.argv[0]),)
        sys.exit(0)
    
    #---------------------------------------------------------------------------

    if len(sys.argv) < 2:
        usage()
        
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hqvs:t:",
                                   ("help", "verbose", "quiet",
                                    "start-time=", "end-time=", ))
    except (getopt.error):
        usage()
        
    for (x, y) in opts:        
        if x in ('-h', '--help'):
            usage()

        elif x in ('-q', '--quiet'):
            VERBOSE = 0

        elif x in ('-v', '--verbose'):
            VERBOSE = 2

        elif x in ('-s', '--start-time'):
            START_T = time.mktime(time.strptime(y))

        elif x in ('-t', '--end-time'):
            END_T = time.mktime(time.strptime(y))

    filenames = args
    if not filenames:
        usage()
        
    #---------------------------------------------------------------------------

    for fn in filenames:
        cnt = 0
        try:
            mrt = mrtd.Mrtd(fn, "rb", mrtd.DEFAULT_SIZE)
            error('[ %s ] parsing...' % fn)
            while 1:
                msg = mrt.read()
                if (((START_T < 0) or (msg[0] >= START_T)) and
                    ((END_T   < 0) or (msg[0] <= END_T))):

                    rv  = mrt.parse(msg, VERBOSE)
                    cnt = cnt + 1
                    if VERBOSE > 1:
                        pprint.pprint(rv)

        except (mrtd.EOFExc):
            error("end of file: %u messages\n" % cnt)
        except (KeyboardInterrupt):
            error("interrupted!\n")

        mrt.close()
    sys.exit(0)

################################################################################
################################################################################
