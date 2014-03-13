## Copyright (c) 2014 CORE Security Technologies
##
## This software is provided under under a slightly modified version
## of the Apache Software License. See the accompanying LICENSE file
## for more information.
##

import pcapy
import sys
import unittest

class TestPcapy(unittest.TestCase):
    _96PINGS = '96pings.pcap'
    def testPacketHeaderRefCount(self):
        """#1:when next() creates a pkthdr it make one extra reference"""
        class _Simple: pass
        #r = pcapy.open_live("en1", 65000, 0, 1000)
        r = pcapy.open_offline(TestPcapy._96PINGS)
        #get one & check its refcount
        self.assertEqual( sys.getrefcount(r.next()[0]),
                          sys.getrefcount(_Simple()) )
    def testEOFValue(self):
        """#1:when next() creates a pkthdr it make one extra reference"""
        class _Simple: pass
        #r = pcapy.open_live("en1", 65000, 0, 1000)
        r = pcapy.open_offline(TestPcapy._96PINGS)
        #get one & check its refcount
        i=0
        refNone = sys.getrefcount(None)
        s = r.next()
        while not s[0] is None:
            s = r.next()
            i+=1
        self.assertEqual( 96, i )
        self.assertEqual( s[0], None )
        self.assertEqual( s[1], '' )
        del s
        self.assertEqual( refNone, sys.getrefcount(None) )

suite = unittest.TestLoader().loadTestsFromTestCase(TestPcapy)

suite = unittest.TestLoader().loadTestsFromTestCase(TestPcapy)
unittest.TextTestRunner(verbosity=2).run(suite)
