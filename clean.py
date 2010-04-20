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
# $Id: clean.py,v 1.2 2002/01/26 23:55:15 mort Exp $
#

import os, time, struct, getopt, sys, bgp, isis, mrtd, pprint
from mutils import *

################################################################################

if __name__ == "__main__":

    VERBOSE = 1

    #---------------------------------------------------------------------------

    def usage():

        print """Usage: %s [ options ] <filenames>:
        -h|--help      : Help
        -v|--verbose   : Be verbose
        -q|--quiet     : Be quiet""" %\
            (os.path.basename(sys.argv[0]),)
        sys.exit(0)
    
    #---------------------------------------------------------------------------

    if len(sys.argv) < 2:
        usage()
        
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hqv",
                                   ("help", "verbose", "quiet", ))
    except (getopt.error):
        usage()
        
    for (x, y) in opts:        
        if x in ('-h', '--help'):
            usage()

        elif x in ('-q', '--quiet'):
            VERBOSE = 0

        elif x in ('-v', '--verbose'):
            VERBOSE = 2

    filenames = args
    if not filenames:
        usage()
        
    #---------------------------------------------------------------------------

    verbose = VERBOSE-1
    if verbose < 0:
        verbose = 0
    for fn in filenames:
        cnt = 0
        try:
            of  = open(fn + '.clean', 'w+b')
            mrt = mrtd.Mrtd(fn, "rb", mrtd.DEFAULT_SIZE)
            error('[ %s ] cleaning...' % fn)
            while 1:
                cnt = cnt + 1
                msg_tup = mrt.read()
                msg = msg_tup[-2] + msg_tup[-1]
                
                try:
                    rv = mrt.parse(msg_tup, verbose)

                except (KeyboardInterrupt):
                    raise KeyboardInterrupt
                
                except:
                    rv["T"] = None

                if rv["T"]:
                    of.write(msg)
                else:
                    if VERBOSE:
                        print prthex("msg %d: " % cnt, msg)
                    error('msg %d dirty...' % cnt)
                    
        except (mrtd.EOFExc):
            error("end of file: %u messages\n" % cnt)
        except (KeyboardInterrupt):
            error("interrupted!\n")

        mrt.close()
        of.close()
    sys.exit(0)

################################################################################
################################################################################
