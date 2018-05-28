## Copyright (c) 2014 CORE Security Technologies
##
## This software is provided under under a slightly modified version
## of the Apache Software License. See the accompanying LICENSE file
## for more information.
##

import pcapy
import sys
import unittest
import os


class TestPcapy(unittest.TestCase):

    _96PINGS = '96pings.pcap'
    _IFACE = 'vboxnet0'

    def testPacketHeaderRefCount(self):
        """
        #1: when next() creates a pkthdr it makes one extra reference
        """

        class _Simple:
            pass

        r = pcapy.open_offline(TestPcapy._96PINGS)

        # get one & check its refcount
        self.assertEqual(
            sys.getrefcount(r.next()[0]),
            sys.getrefcount(_Simple()))

    def testEOFValue(self):
        """
        #2 empty string is returned as packet body at end of file
        """

        r = pcapy.open_offline(TestPcapy._96PINGS)
        # get one & check its refcount

        i = 0
        refNone = sys.getrefcount(None)
        hdr, pkt = r.next()
        while hdr is not None:
            hdr, pkt = r.next()
            i += 1
        self.assertEqual(96, i)
        self.assertTrue(hdr is None)
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

    def _testLiveCapture(self):
        """
        #4 (disabled -- requires interface info) test live capture
        """
        r = pcapy.open_live(TestPcapy._IFACE, 60000, 1, 1500)
        net = r.getnet()
        self.assertEqual(net, '192.168.56.0')
        hdr, body = r.next()
        self.assertTrue(hdr is not None)

    def _testSendPacket(self):
        """
        #5 (disabled -- requires interface info) test sendpacket
        """
        r = pcapy.open_offline(TestPcapy._96PINGS)
        w = pcapy.open_live(TestPcapy._IFACE, 60000, 1, 1500)
        # get one & check its refcount

        i = 0
        hdr, pkt = r.next()
        while hdr is not None:
            w.sendpacket(pkt)
            hdr, pkt = r.next()
            i += 1

    def testPacketDumper(self):
        """
        #6 test that the dumper writes correct payload
        """
        try:
            r = pcapy.open_offline(TestPcapy._96PINGS)
            dumper = r.dump_open('tmp.pcap')

            hdr, body = r.next()
            i = 0
            while hdr is not None:
                dumper.dump(hdr, body)
                i += 1
                hdr, body = r.next()

            # make sure file closes
            del dumper

            # check that the dumper wrote a legal pcap
            # file with same packer data
            r = pcapy.open_offline(TestPcapy._96PINGS)
            r2 = pcapy.open_offline('tmp.pcap')

            h1, b1 = r.next()
            h2, b2 = r2.next()
            while h1 is not None and h2 is not None:
                self.assertEqual(b1, b2)
                h1, b1 = r.next()
                h2, b2 = r2.next()

            self.assertTrue(h1 is None)
            self.assertTrue(h2 is None)
            del r2
        finally:
            os.unlink('tmp.pcap')

    def testClose(self):
        """
        #7 Test the close method
        """
        r = pcapy.open_offline(TestPcapy._96PINGS)
        hdr, body = r.next()
        assert hdr is not None
        r.close()
        with self.assertRaises(ValueError):
            r.next()

    def testContextManager(self):
        """
        #8 Test the context manager support
        """
        with pcapy.open_offline(TestPcapy._96PINGS) as r:
            hdr, body = r.next()
            assert hdr is not None

        with self.assertRaises(ValueError):
            r.next()

    def test_get_bpf(self):
        bpf = pcapy.compile(pcapy.DLT_EN10MB, 2**16, "icmp", 1, 1)
        code = bpf.get_bpf()

        # result of `tcpdump "icmp" -ddd -s 65536` on EN10MB interface
        expected = """6
40 0 0 12
21 0 3 2048
48 0 0 23
21 0 1 1
6 0 0 65536
6 0 0 0"""

        result = str(len(code)) + "\n"
        result += "\n".join([' '.join(map(str, inst)) for inst in code])

        self.assertEqual(expected, result)


suite = unittest.TestLoader().loadTestsFromTestCase(TestPcapy)
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful():
    sys.exit(1)
