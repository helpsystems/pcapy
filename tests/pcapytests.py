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
        """
        #1: when next() creates a pkthdr it makes one extra reference
        """

        class _Simple:
            pass

        # r = pcapy.open_live("en1", 65000, 0, 1000)
        r = pcapy.open_offline(TestPcapy._96PINGS)
        # get one & check its refcount
        self.assertEqual(
            sys.getrefcount(r.next()[0]),
            sys.getrefcount(_Simple()))

    def testEOFValue(self):
        """
        #2 empty string is returned as packet body at end of file
        """
        class _Simple:
            pass

        # r = pcapy.open_live("en1", 65000, 0, 1000)

        r = pcapy.open_offline(TestPcapy._96PINGS)
        # get one & check its refcount

        i = 0
        refNone = sys.getrefcount(None)
        hdr, pkt = r.next()
        while hdr is not None:
            hdr, pkt = r.next()
            i += 1
        self.assertEqual(96, i)
        self.assertIsNone(hdr, None)
        self.assertEqual(pkt, b'')
        del hdr
        self.assertEqual(refNone, sys.getrefcount(None))

    def testBPFFilter(self):
        """
        #3 test offline BPFFilter
        """
        r = pcapy.open_offline(TestPcapy._96PINGS)
        bpf = pcapy.BPFProgram("ip dst host 192.168.1.1")

        hdr, pkt = r.next()
        while hdr is not None:
            f = bpf.filter(pkt)
            self.assertNotEqual(f, 0)
            hdr, pkt = r.next()

suite = unittest.TestLoader().loadTestsFromTestCase(TestPcapy)
unittest.TextTestRunner(verbosity=2).run(suite)
