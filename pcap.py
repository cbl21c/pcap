#!/usr/bin/python

import sys
import struct

# global variables
sizeof_int32  = 4
sizeof_uint32 = 4
sizeof_uint16 = 2

MAGIC_LITTLE_ENDIAN_USEC = 0xa1b2c3d4
MAGIC_BIG_ENDIAN_USEC    = 0xd4c3b2a1
MAGIC_LITTLE_ENDIAN_NSEC = 0xa1b23c4d
MAGIC_BIG_ENDIAN_NSEC    = 0x4d3cb2a1

USEC_RESOLUTION = 0x06
NSEC_RESOLUTION = 0x09

# self reference to module so that we don't have to globalise all the variables
# but we will have to reference them as pcap.varname
pcap = sys.modules[__name__]


class PcapRecord:
    def __init__(self,
        ts_sec = 0,
        ts_usec = 0,
        incl_len = 0,
        orig_len = 0,
        data = None):

        self.ts_sec   = 0
        self.ts_usec  = 0
        self.incl_len = 0
        self.orig_len = 0
        self.data     = None

        if ts_sec is not None:
            self.ts_sec = ts_sec
        if ts_usec is not None:
            self.ts_usec  = ts_usec
        if incl_len is not None:
            self.incl_len = incl_len
        if orig_len is not None:
            self.orig_len = orig_len
        if data is not None:
            self.data = data


class PcapFile:
    # class variables go here


    def __init__(self, filename=None):
        self.fname = filename

        # these attributes are from struct pcap_hdr_s
        self.magic_number  = None
        self.version_major = None
        self.version_minor = None
        self.thiszone      = None
        self.sigfigs       = None
        self.snaplen       = None
        self.network       = None

        # attributes derived from the above
        self.endian        = None
        self.resolution    = None
        self.num_records   = 0


##############################
#   read()                   #
##############################
    def read(self):

        if self.fname is None:
            return

        try:
            pf = open(self.fname, 'rb')
            # read the global header first
            self.header = pf.read(24)
        except IOError:
            sys.stderr.write("Could not open file %s\n" % self.fname)
            return

        #
        # now parse the global header...
        #

        # ... magic number; this will determine endian and resolution
        fmt = '<I'
        self.endian = '<'
        ptr = 0
        magic = struct.unpack(fmt, self.header[ptr:ptr + pcap.sizeof_uint32])[0]

        if magic == pcap.MAGIC_LITTLE_ENDIAN_USEC:
            self.magic_number = magic
            self.resolution = pcap.USEC_RESOLUTION
        elif magic == pcap.MAGIC_BIG_ENDIAN_USEC:
            self.endian = '>'
            self.magic_number = struct.unpack(uint32, self.header[ptr:ptr + pcap.sizeof_uint32])[0]
            self.resolution = pcap.USEC_RESOLUTION
        elif magic == pcap.MAGIC_LITTLE_ENDIAN_NSEC:
            self.magic_number = magic
            self.resolution = pcap.NSEC_RESOLUTION
        elif magic == pcap.MAGIC_BIG_ENDIAN_NSEC:
            self.endian = '>'
            self.magic_number = struct.unpack(uint32, self.header[ptr:ptr + pcap.sizeof_uint32])[0]
            self.resolution = pcap.NSEC_RESOLUTION
        else:
            # invalid magic number
            sys.stderr.write("Invalid pcap file (magic number error)\n")
            pf.close()
            return

        ptr = ptr + pcap.sizeof_uint32

        # ... the rest of the global self.header
        fmt = self.endian + 'HHiIII'
        (self.version_major, self.version_minor, self.thiszone, self.sigfigs, self.snaplen, self.network) = struct.unpack(fmt, self.header[ptr:ptr + 20])
        ptr = ptr + 2 * pcap.sizeof_uint16 + pcap.sizeof_int32 + 3 * pcap.sizeof_uint32


        # now read the rest of the file and parse into individual records
        rawData = pf.read()
        endOfData = len(rawData)

        self.packetList = []
        ptr = 0

        while ptr < endOfData:
            # read record header - gives us the length of the packet
            fmt = self.endian + 'IIII'
            (ts_sec, ts_usec, incl_len, orig_len) = struct.unpack(fmt, rawData[ptr:ptr + 16])
            ptr = ptr + 16

            # read the packet data
            fmt = '%dB' % incl_len
            data = struct.unpack(fmt, rawData[ptr:ptr + incl_len])
            packet = PcapRecord(ts_sec, ts_usec, incl_len, orig_len, data)
            self.packetList.append(packet)
            self.num_records = self.num_records + 1
            ptr = ptr + incl_len

        pf.close()


##############################
#   writeto()                #
##############################
    def writeto(self, fname):

        if fname is None:
            return

        try:
            outfile = open(fname, 'wb')
        except IOError:
            sys.stderr.write("Could not write to file %s\n" % fname)
            return

        # write the global header
        outfile.write(self.header)

        # now iterate over the record list
        for n in range(self.num_records):
            pkt = self.packetList[n]
            ts_sec   = pkt.ts_sec
            ts_usec  = pkt.ts_usec
            incl_len = pkt.orig_len
            orig_len = pkt.orig_len
            data     = pkt.data
            fmt = self.endian + 'IIII'
            outfile.write(struct.pack(fmt, ts_sec, ts_usec, incl_len, orig_len))
            fmt = '%dB' % incl_len
            outfile.write(struct.pack(fmt, *data))

        outfile.close()


##############################
#   delete()                 #
##############################
    def delete(self, x):
        if x < 0 or x >= self.num_records:
            return

        del self.packetList[x]


##############################
#   swap()                   #
##############################
    def swap(self, a, b):
        if a is None or b is None:
            return

        if a < 0 or b < 0 or a >= self.num_records or b >= self.num_records:
            return;

        if a == b:
            return;

        apkt = self.packetList[a]
        bpkt = self.packetList[b]

        anew = PcapRecord(apkt.ts_sec, apkt.ts_usec, bpkt.incl_len, bpkt.orig_len, bpkt.data)
        bnew = PcapRecord(bpkt.ts_sec, bpkt.ts_usec, apkt.incl_len, apkt.orig_len, apkt.data)
        self.packetList[a] = anew
        self.packetList[b] = bnew


##############################
#   relocate()               #
##############################
    def relocate(self, src, dst):
        if src is None or dst is None:
            return

        if src < 0 or src >= self.num_records:
            return

        if dst < 0:
            dst = 0

        if dst >= self.num_records:
            dst = self.num_records - 1

        if src == dst:
            return

        refpkt = [None] * (abs(dst - src) + 1)
        newpkt = [None] * (abs(dst - src) + 1)

        # relocate a packet to a later time, ie. dst > src
        if dst > src:
            for n in range(src, dst + 1):
                refpkt[n - src] = self.packetList[n]

            for n in range(src, dst):
                newpkt[n - src] = pcap.PcapRecord(
                                      refpkt[n - src].ts_sec,
                                      refpkt[n - src].ts_usec,
                                      refpkt[n - src + 1].incl_len,
                                      refpkt[n - src + 1].orig_len,
                                      refpkt[n - src + 1].data)

            newpkt[dst - src] = pcap.PcapRecord(
                                      refpkt[dst - src].ts_sec,
                                      refpkt[dst - src].ts_usec,
                                      refpkt[0].incl_len,
                                      refpkt[0].orig_len,
                                      refpkt[0].data)

            for n in range(src, dst + 1):
                self.packetList[n] = newpkt[n - src]

        # relocate a packet to an earlier time, ie. dst < src
        else:
            for n in range(src, dst - 1, -1):
                refpkt[n - dst] = self.packetList[n]

            for n in range(src, dst, -1):
                newpkt[n - dst] = pcap.PcapRecord(
                                      refpkt[n - dst].ts_sec,
                                      refpkt[n - dst].ts_usec,
                                      refpkt[n - dst - 1].incl_len,
                                      refpkt[n - dst - 1].orig_len,
                                      refpkt[n - dst - 1].data)

            newpkt[0] = pcap.PcapRecord(
                                      refpkt[0].ts_sec,
                                      refpkt[0].ts_usec,
                                      refpkt[src - dst].incl_len,
                                      refpkt[src - dst].orig_len,
                                      refpkt[src - dst].data)

            for n in range(src, dst - 1, -1):
                self.packetList[n] = newpkt[n - dst]


