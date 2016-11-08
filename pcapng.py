#!/usr/bin/python

import sys
import math
import struct

#
# global variables
#
sizeof_uint16 = 2
sizeof_int32  = 4
sizeof_uint32 = 4
sizeof_int64  = 8

# standardised block type codes
SECTION_IDB = 0x00000001	# Interface Description Block
APPENDIX_PB = 0x00000002	# Packet Block (obsoleted)
SECTION_SPB = 0x00000003	# Simple Packet Block
SECTION_NRB = 0x00000004	# Name Resolution Block
SECTION_ISB = 0x00000005	# Interface Statistics Block
SECTION_EPB = 0x00000006	# Enhanced Packet Block
SECTION_SHB = 0x0a0d0d0a	# Section Header Block

MAGIC_LITTLE_ENDIAN = 0x1a2b3c4d
MAGIC_BIG_ENDIAN    = 0x4d3c2b1a

LITTLE_ENDIAN = '<'
BIG_ENDIAN    = '>'
USEC_RESOLUTION = 0x06
NSEC_RESOLUTION = 0x09

NULL_OPTION = 0x0000


# self reference to module so that we don't have to globalise all the variables
# but we will have to reference them as pcapng.varname
pcapng = sys.modules[__name__]


#
# base class for Pcapng blocks
#
class PcapngBlock:
    def __init__(self):
        self.blockType   = None
        self.blockLength = None
        self.rawData     = None

class SectionHeaderBlock(PcapngBlock):
    SHB_HARDWARE = 2
    SHB_OS       = 3
    SHB_USERAPPL = 4

    def __init__(self, endian='@', byteData=None):
        # call the constructor from the base class first
        PcapngBlock.__init__(self)

        self.magic         = None
        self.endian        = None
        self.major         = None
        self.minor         = None
        self.sectionLength = None
        self.shb_hardware  = None
        self.shb_os        = None
        self.shb_userappl  = None

        if byteData is None:
            return

        ptr = 0
        fmt = endian + 'IIIHHq'
        self.rawData = byteData
        (self.blockType, self.blockLength, self.magic, self.major, self.minor, self.sectionLength) = struct.unpack(fmt, byteData[ptr:ptr + 24])

        # check the endianness from the magic number
        if self.magic == pcapng.MAGIC_LITTLE_ENDIAN:
            self.endian = pcapng.LITTLE_ENDIAN
        elif self.magic == pcapng.MAGIC_BIG_ENDIAN:
            self.endian = pcapng.BIG_ENDIAN
        else:
            return

        ptr = ptr + 24
        option = None
        fmt = endian + 'HH'
        while option != pcapng.NULL_OPTION:
            (option, length) = struct.unpack(fmt, byteData[ptr:ptr + 4])
            ptr = ptr + 4

            if option == self.SHB_HARDWARE:
                self.shb_hardware = byteData[ptr:ptr + length]
            if option == self.SHB_OS:
                self.shb_os = byteData[ptr:ptr + length]
            if option == self.SHB_USERAPPL:
                self.shb_userappl = byteData[ptr:ptr + length]

            if length % 4 > 0:
                pad = 4 - length % 4

            ptr = ptr + length + pad


    def dump(self):
        sys.stdout.write("section_shb:\n")
        sys.stdout.write("\ttotal length: %d\n" % self.blockLength)
        sys.stdout.write("\tmagic: 0x%08x\n" % self.magic)
        sys.stdout.write("\tmajor version: %d\n" % self.major)
        sys.stdout.write("\tminor version: %d\n" % self.minor)
        sys.stdout.write("\tsection length: %d\n" % self.sectionLength)

        if self.shb_hardware is not None:
            sys.stdout.write("\tshb_hardware: %s\n" % self.shb_hardware)
        if self.shb_os is not None:
            sys.stdout.write("\tshb_os: %s\n" % self.shb_os)
        if self.shb_userappl is not None:
            sys.stdout.write("\tshb_userappl: %s\n" % self.shb_userappl)


class InterfaceDescriptionBlock(PcapngBlock):
    IF_NAME        = 2
    IF_DESCRIPTION = 3
    IF_IPV4ADDR    = 4
    IF_IPV6ADDR    = 5
    IF_MACADDR     = 6
    IF_EUIADDR     = 7
    IF_SPEED       = 8
    IF_TSRESOL     = 9
    IF_TZONE       = 10
    IF_FILTER      = 11
    IF_OS          = 12
    IF_FCSLEN      = 13
    IF_TSOFFSET    = 14

    def __init__(self, endian='@', byteData=None):
        # call the constructor from the base class first
        PcapngBlock.__init__(self)

        self.linktype       = None
        self.snaplen        = None
        self.if_name        = None
        self.if_description = None
        self.if_ipv4addr    = None
        self.if_ipv6addr    = None
        self.if_macaddr     = None
        self.if_euiaddr     = None
        self.if_speed       = None
        self.if_tsresol     = None
        self.if_tzone       = None
        self.if_filter      = None
        self.if_os          = None
        self.if_fcslen      = None
        self.if_tsoffset    = None

        if byteData is None:
            return

        ptr = 0
        fmt = endian + 'IIHHI'
        self.rawData = byteData
        (self.blockType, self.blockLength, self.linktype, reserved, self.snaplen) = struct.unpack(fmt, byteData[ptr:ptr + 16])

        ptr = ptr + 16
        option = None
        fmt = endian + 'HH'
        while option != pcapng.NULL_OPTION:
            (option, length) = struct.unpack(fmt, byteData[ptr:ptr + 4])
            ptr = ptr + 4

            if option == self.IF_NAME:
                self.if_name = byteData[ptr:ptr + length]
            if option == self.IF_DESCRIPTION:
                self.if_description = byteData[ptr:ptr + length]
            if option == self.IF_IPV4ADDR:
                self.if_ipv4addr = byteData[ptr:ptr + length]
            if option == self.IF_IPV6ADDR:
                self.if_ipv6addr = byteData[ptr:ptr + length]
            if option == self.IF_MACADDR:
                self.if_macaddr = byteData[ptr:ptr + length]
            if option == self.IF_EUIADDR:
                self.if_euiaddr = byteData[ptr:ptr + length]
            if option == self.IF_SPEED:
                fmt = endian + 'Q'
                self.if_speed = struct.unpack(fmt, byteData[ptr:ptr + length])[0]
                fmt = endian + 'HH'
            if option == self.IF_TSRESOL:
                fmt = 'B'
                self.if_tsresol = struct.unpack(fmt, byteData[ptr])[0]
                fmt = endian + 'HH'
            if option == self.IF_TZONE:
                # correction time in seconds from UTC
                fmt = endian + 'i'
                self.if_tzone = struct.unpack(fmt, byteData[ptr:ptr + length])[0]
                fmt = endian + 'HH'
            if option == self.IF_FILTER:
                self.if_filter = byteData[ptr:ptr + length]
            if option == self.IF_OS:
                self.if_os = byteData[ptr:ptr + length]
            if option == self.IF_FCSLEN:
                fmt = 'B'
                self.if_fcslen = struct.unpack(fmt, byteData[ptr])[0]
                fmt = endian + 'HH'
            if option == self.IF_TSOFFSET:
                fmt = endian + 'q'
                self.if_tsoffset = struct.unpack(fmt, byteData[ptr:ptr + length])[0]
                fmt = endian + 'HH'

            if length % 4 > 0:
                pad = 4 - length % 4

            ptr = ptr + length + pad


    def dump(self):
        sys.stdout.write("section_idb:\n")
        sys.stdout.write("\ttotal length: %d\n" % self.blockLength)
        sys.stdout.write("\tlink type: %d\n" % self.linktype)
        sys.stdout.write("\tsnaplen: %d\n" % self.snaplen)

        if self.if_name is not None:
            sys.stdout.write("\tif_name: %s\n" % self.if_name)
        if self.if_description is not None:
            sys.stdout.write("\tif_description: %d\n" % self.if_description)
        if self.if_ipv4addr is not None:
            bytes = bytearray(self.if_ipv4addr)
            sys.stdout.write("\tif_ipv4addr: %d.%d.%d.%d\n" \
                %(bytes[0], bytes[1], bytes[2], bytes[3]))
            sys.stdout.write("\tif_netmask: %d.%d.%d.%d\n" \
                %(bytes[4], bytes[5], bytes[6], bytes[7]))
        if self.if_ipv6addr is not None:
            bytes = bytearray(self.if_ipv6addr)
            sys.stdout.write("\tif_ipv6addr: ")
            for n in range(8):
                sys.stdout.write("%02x%02" %(bytes[n * 2], bytes[n * 2 + 1]))
                if n < 7:
                    sys.stdout.write(":")
                else:
                    sys.stdout.write("/%d\n", bytes[16])
        if self.if_macaddr is not None:
            bytes = bytearray(self.if_macaddr)
            sys.stdout.write("\tif_macaddr: %02x:%02x:%02x:%02:%02x:%02xx\n" \
                %(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]))
        if self.if_euiaddr is not None:
            bytes = bytearray(self.if_euiaddr)
            sys.stdout.write("\tif_euiaddr: ")
            for n in range(64):
                sys.stdout.write("%02x " % bytes[n])
            sys.stdout.write("\n")
        if self.if_speed is not None:
            mbps = self.if_speed / 1000000
            sys.stdout.write("\tif_speed: %d Mbps\n" % mbps)
        if self.if_tsresol is not None:
            sys.stdout.write("\tif_tsresol: ")
            sign = self.if_tsresol >> 7
            exp = self.if_tsresol & 0x7f
            if sign == 0:
                sys.stdout.write("10E-%d\n" % exp)
            else:
                resol = 2 ** exp
                sys.stdout.write("1/%ds\n" % resol)
        if self.if_tzone is not None:
            if self.if_tzone < 0:
                sign = -1
            elif self.if_tzone == 0:
                sign = 0
            elif self.if_tzone > 0:
                sign = 1

            hours = int(sign * self.if_tzone / 3600)
            mins  = sign * self.if_tzone - hours * 60
            sys.stdout.write("\tif_tzone: UTC")

            if sign > 0:
                sys.stdout.write("+%02d:%02d\n" %(hours, mins))
            elif sign < 0:
                sys.stdout.write("-%02d:%02d\n" %(hours, mins))
            else:
                sys.stdout.write("\n")

        if self.if_filter is not None:
            sys.stdout.write("\tif_filter: %s\n" % self.if_filter[1:])
        if self.if_os is not None:
            sys.stdout.write("\tif_os: %s\n" % self.if_os)
        if self.if_fcslen is not None:
            sys.stdout.write("\tif_fcslen: %d\n" % self.if_fcslen)
        if self.if_tsoffset is not None:
            sys.stdout.write("\tif_tsoffset: %d\n" % self.if_tsoffset)


class EnhancedPacketBlock(PcapngBlock):
    EPB_FLAGS     = 2
    EPB_HASH      = 3
    EPB_DROPCOUNT = 4

    def __init__(self, endian='@', byteData=None):
        # call the constructor from the base class first
        PcapngBlock.__init__(self)

        self.interfaceId    = None
        self.timestamp_high = None
        self.timestamp_low  = None
        self.capturedLength = None
        self.originalLength = None
        self.packetData     = None
        self.epb_flags      = None
        self.epb_hash       = None
        self.epb_dropcount  = None

        if byteData is None:
            return

        ptr = 0
        fmt = endian + 'IIIIIII'
        self.rawData = byteData
        (self.blockType, self.blockLength, self.interfaceId, self.timestamp_high, self.timestamp_low, self.capturedLength, self.originalLength) = struct.unpack(fmt, byteData[ptr:ptr + 28])

        ptr = ptr + 28
        option = None
        fmt = endian + 'HH'
        while option != pcapng.NULL_OPTION:
            (option, length) = struct.unpack(fmt, byteData[ptr:ptr + 4])
            ptr = ptr + 4

            if option == self.EPB_FLAGS
                self.epb_flags = byteData[ptr:ptr + length]
            if option == self.EPB_HASH:
                self.epb_hash = byteData[ptr:ptr + length]
            if option == self.EPB_DROPCOUNT:
                fmt = endian + 'Q'
                self.epb_dropcount = struct.unpack(fmt, byteData[ptr:ptr + length])[0]
                fmt = endian + 'HH'

            if length % 4 > 0:
                pad = 4 - length % 4

            ptr = ptr + length + pad


    def dump(self):
        sys.stdout.write("section_epb:\n")
        sys.stdout.write("\ttotal length: %d\n" % self.blockLength)

        if self.if_name is not None:
            sys.stdout.write("\tif_name: %s\n" % self.if_name)


class PcapngFile:
    # class variables go here


    def __init__(self, filename=None):
        self.fname = filename

        # other attributes
        self.num_blocks = 0
        self.blockList = []


##############################
#   read()                   #
##############################
    def read(self):

        if self.fname is None:
            return

        try:
            pf = open(self.fname, 'rb')
            # read the entire file
            self.rawData = pf.read()
            endOfData = len(self.rawData)
            pf.close
        except IOError:
            sys.stderr.write("Could not open file %s\n" % self.fname)
            return

        endian = None
        fmt = '<II'
        ptr = 0

        # read through each block
        while ptr < endOfData:
            (blockType, blockLength) = \
                struct.unpack(fmt, self.rawData[ptr:ptr + 2 * pcapng.sizeof_uint32])

            # first block must be a section header block
            if endian is None and blockType != pcapng.SECTION_SHB:
                sys.stderr.write("Invalid pcapng file %s\n" % self.fname)
                return

            if blockType == pcapng.SECTION_SHB:
                # read the magic number to determine endianness
                fmt = pcapng.LITTLE_ENDIAN + 'I'
                ptr = ptr + 8
                magic = struct.unpack(fmt, self.rawData[ptr:ptr + pcapng.sizeof_uint32])[0]
                if magic == pcapng.MAGIC_LITTLE_ENDIAN:
                    endian = pcapng.LITTLE_ENDIAN
                elif magic == pcapng.MAGIC_BIG_ENDIAN:
                    endian = pcapng.BIG_ENDIAN
                else:
                    sys.stderr.write("Invalid magic number %08x\n" % magic)
                    return

                # read the block type and length again, in case the endian has changed
                fmt = endian + 'II'
                ptr = ptr - 8
                (blockType, blockLength) = \
                    struct.unpack(fmt, self.rawData[ptr:ptr + 2 * pcapng.sizeof_uint32])

                rec = pcapng.SectionHeaderBlock(endian, self.rawData[ptr:ptr + blockLength])
                self.blockList.append(rec)
                rec.dump()

            elif blockType == pcapng.SECTION_IDB:
                rec = pcapng.InterfaceDescriptionBlock(endian, self.rawData[ptr:ptr + blockLength])
                self.blockList.append(rec)
                rec.dump()
                # sys.stdout.write("section_idb: ")
            elif blockType == pcapng.APPENDIX_PB:
                sys.stdout.write("appendix_pb\n")
            elif blockType == pcapng.SECTION_SPB:
                sys.stdout.write("section_spb\n")
            elif blockType == pcapng.SECTION_NRB:
                sys.stdout.write("section_nrb\n")
            elif blockType == pcapng.SECTION_ISB:
                sys.stdout.write("section_isb\n")
            elif blockType == pcapng.SECTION_EPB:
                sys.stdout.write("section_epb\n")
            else:
                sys.stdout.write("Unknown block\n")

            self.num_blocks = self.num_blocks + 1
            # self.blockList.append(self.rawData[ptr:ptr + blockLength])
            ptr = ptr + blockLength

##############################
#   dump()                   #
##############################
    def dump(self, start=None, end=None):
        pass




