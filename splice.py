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
# $Id: splice.py,v 1.8 2002/02/06 16:58:46 mort Exp $
#

import time, getopt, sys, mrtd, string, os
from mutils import *

################################################################################

class Msg:

    def __init__(self, mrt, msg):

        self._mrt  = mrt
        self._msg  = msg
        self._time = msg[0]

    def __repr__(self):

        return "%s: %s" % (self._mrt._file_name, `self._time`)
        
    def __cmp__(self, other):

        if   self._time <  other._time: return -1
        elif self._time == other._time: return 0
        else:                           return 1

    def parse(self, verbose):

        return self._mrt.parse(self._msg, verbose)

################################################################################

if __name__ == "__main__":

    VERBOSE = 1
    START_T = -1
    END_T   = -1

    file_size = mrtd.MIN_FILE_SZ
    file_pfx  = mrtd.DEFAULT_FILE
    extn_fmt  = ".%Y-%m-%d_%H.%M.%S"

    #---------------------------------------------------------------------------

    def usage():

        print """Usage: %s [ options ] <filenames>:
        -h|--help         : Help
        -q|--quiet        : Be quiet
        -v|--verbose      : Be verbose
        -V|--very-verbose : Be very verbose

        -f|--file         : Filename prefix for output
        -z|--file-size    : Size of output file(s) [min: %d]
        -s|--start-time   : Start time of packets of interest [inclusive]
        -t|--end-time     : End time of packets of interest [inclusive]""" %\
            (os.path.basename(sys.argv[0]), mrtd.MIN_FILE_SZ)
        sys.exit(0)
    
    #---------------------------------------------------------------------------

    if len(sys.argv) < 2:
        usage()
        
    try:
        try:
            opts, args =\
                  getopt.getopt(sys.argv[1:],
                                "hqvVf:t:z:s:t:",
                                ("help", "quiet", "verbose", "very-verbose",
                                 "file=", "size=", "start-time=", "end-time=" ))
        except (getopt.error):
            usage()

        for (x, y) in opts:        
            if x in ('-h', '--help'):
                usage()

            elif x in ('-q', '--quiet'):
                VERBOSE = 0

            elif x in ('-v', '--verbose'):
                VERBOSE = 2

            elif x in ('-V', '--very-verbose'):
                VERBOSE = 3

            elif x in ('-z', '--size'):
                file_size = max(string.atof(y), mrtd.MIN_FILE_SZ)

            elif x in ('-f', '--file'):
                file_pfx = y

            elif x in ('-s', '--start-time'):
                START_T = time.mktime(time.strptime(y))

            elif x in ('-t', '--end-time'):
                END_T = time.mktime(time.strptime(y))
                
            else:
                usage()

        filenames = args
        if not filenames:
            usage()

        #-----------------------------------------------------------------------

        msgs  = []
        mrtds = {}

        for f in filenames:            
            mrtds[f] = mrtd.Mrtd(f, "rb")
            try:
                while 1:
                    msg = mrtds[f].read()
                    if (((START_T < 0) or (msg[0] >= START_T)) and
                        ((END_T   < 0) or (msg[0] <= END_T))):
                        
                        msgs.append( Msg(mrtds[f], msg) )
                        break
                    
            except (mrtd.EOFExc):
                del mrtds[f]
                
        msgs.sort()
        of = open(file_pfx+
                  time.strftime(extn_fmt, time.gmtime(msgs[0]._time)),
                  "w+b")

        while len(msgs) > 0:            
            try:
                msg = msgs[0]._msg[-2] + msgs[0]._msg[-1]

                if of.tell()+len(msg) > file_size:
                    of.close()
                    of = open(file_pfx+
                              time.strftime(extn_fmt,
                                            time.localtime(msgs[0]._time)),
                              "w+b")

                if (((START_T < 0) or (msgs[0]._time >= START_T)) and
                    ((END_T   < 0) or (msgs[0]._time <= END_T))):

                    of.write(msg)
                    if VERBOSE > 2:
                        print prtbin("", msg)
                    rv = msgs[0].parse(VERBOSE)

                msg = msgs[0]._mrt.read()
                msgs[0] = Msg(msgs[0]._mrt, msg)
                msgs.sort()
                
            except (mrtd.EOFExc):
                del msgs[0]
                
    except (KeyboardInterrupt):
        print "Interrupted"

    sys.exit(0)

################################################################################
################################################################################
