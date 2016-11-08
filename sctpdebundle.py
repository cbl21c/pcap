#!/usr/bin/python

#
# debundles sctp chunks from pcap file
# and writes one chunk per packet into 
# new pcap file
# non-sctp packets are written unmodified
#
# usage: onedc.py [-h] [-d] -i INFILE -o OUTFILE
#

import sys
from struct import pack, unpack
import argparse
import tcpdump
import protocols.ethernet
import protocols.ip
import protocols.sctp


########################################################
#                                                      #
#  write_packet()                                      #
#                                                      #
#  writes a pcap record to file given the file handle  #
#  and the record data                                 #
#                                                      #
########################################################
def write_packet(fh, endian, ts_sec, ts_usec, incl_len, orig_len, data):
    fmt = endian + "IIII"
    fh.write(pack(fmt, ts_sec, ts_usec, incl_len, orig_len))
    fh.write(str(bytearray(data)))


################################
#                              #
#  main()                      #
#                              #
################################

# instantiate an argument parser
parser = argparse.ArgumentParser(description="Debundle SCTP chunks from pcap file and writes one chunk per packet in new pcap file")

# add optional argument for debugging
parser.add_argument("-d", dest="debug", action="store_true", help="turn debugging on")

# add mandatory arguments for the input and output files
parser.add_argument("-i", dest="infile", required=True, help="input file")
parser.add_argument("-o", dest="outfile", required=True, help="output file")


# parse the arguments
args = parser.parse_args()


try:
    with open(args.infile, 'rb') as pf:
        # read the entire file contents into pcapData
        pcapData = pf.read()
except IOError:
    sys.stderr.write("Could not open input file %s\n" % args.infile)
    sys.exit()

fsize = len(pcapData)

ptr = 0
npackets = 0

# read the magic number and determine
# if file is big or little endian encoded
magic_number = unpack('<I', pcapData[0:4])[0]
if (magic_number == 0xa1b2c3d4 or magic_number == 0xa1b23c4d):
    # file is little endian encoded
    endian = "<"
elif (magic_number == 0xd4c3b2a1 or magic_number == 0x4d3cb2a1):
    # file is big endian encoded
    endian = ">"
else:
    print "Invalid pcap file"
    sys.exit()

# format string:
#   I unsigned int 32
#   H unsigned short 16
#   i integer 32
fmt = endian + "IHHiIII"

fields = unpack(fmt, pcapData[0:24])
ptr = ptr + 24

# extract the pcap global header
magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network = fields

if args.debug:
    print "magic_number: %08x" % magic_number
    print "version_major: %d" % version_major
    print "version_minor: %d" % version_minor
    print "thiszone: %d" % thiszone
    print "sigfigs: %d" % sigfigs
    print "snaplen: %d" % snaplen
    print "network: %d\n\n" % network


# only support files where network == Ethernet
if (network != tcpdump.LINKTYPE_ETHERNET):
    sys.stderr.write("pcap network type %d not supported\n" % network)
    sys.exit()

try:
    recap = open(args.outfile, 'wb')
    recap.write(pack(fmt, magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network))
except IOError:
    sys.stderr.write("Could not open output file %s\n" % args.outfile)
    sys.exit()


ts_sec   = 0
ts_usec  = 0
incl_len = 0
orig_len = 0

# read through all the packets
while (ptr < fsize):
    # read the record header
    fmt = endian + "IIII"
    fields = unpack(fmt, pcapData[ptr : ptr + 16])
    ts_sec, ts_usec, incl_len, orig_len = fields
    ptr = ptr + 16

    if args.debug:
        print "> packet %d: %d bytes" % (npackets, incl_len)

    # copy the packet data into a separate list so that we don't have
    # to reference the pcap data from the first record
    data = list(bytearray(pcapData[ptr:ptr + incl_len]))

    # calculate the next ptr before we potentially modify incl_len
    next_packet = ptr + incl_len

    # Ethertype occurs at offset 12: after src(6) and dst(6) MAC addresses
    # and is encoded as big endian uint16
    ptrEthertype = 12
    next_protocol = data[ptrEthertype] * 256 + data[ptrEthertype + 1]

    # while ethertype == 802.1Q CTAG:
    #     move to next ethertype
    while (next_protocol == protocols.ethernet.IEEE802DOT1Q_CTAG):
        ptrEthertype = ptrEthertype + 4
        next_protocol = data[ptrEthertype] * 256 + data[ptrEthertype + 1]

    if args.debug:
        print "> packet %d: ethertype = %04x" %(npackets, next_protocol)

    # if ethertype is not ip, write the packet unmodified
    if (next_protocol != protocols.ethernet.IPV4):
        write_packet(recap, endian, ts_sec, ts_usec, incl_len, orig_len, data)
        ptr = next_packet
        npackets = npackets + 1
        continue

    if args.debug:
        print "> packet %d: ip" % npackets

    # now that we have the lowest level ethertype, we can point to fields in IPv4
    ptrIp = ptrEthertype + 2
    ptrIpLen = ptrIp + 2
    ptrIpProtocol = ptrIp + 9
    ptrIpChecksum = ptrIp + 10
    next_protocol = data[ptrIpProtocol]

    # if protocol is not sctp, write the packet unmodified
    if (next_protocol != protocols.ip.SCTP):
        write_packet(recap, endian, ts_sec, ts_usec, incl_len, orig_len, data)
        ptr = next_packet
        npackets = npackets + 1
        continue

    # and now, point to fields in SCTP
    ptrSctp = ptrIp + 20
    ptrSctpChecksum = ptrSctp + 8
    ptrChunkType = ptrSctp + 12
    ptrChunkLen = ptrChunkType + 2
    # pointer to the sctp payload which doesn't change as we process each chunk
    ptrSctpPayload = ptrChunkType

    if args.debug:
        print "> packet %d: sctp" % npackets

    # copy original packet up to and including sctp common header
    repack = data[0:ptrChunkType]

    # while (chunk)
    #     append chunk to sctp header
    #     calculate ip len and checksum
    #     calculate incl_len and orig_len
    #     write packet
    #     clear sctp payload

    while (ptrChunkType < incl_len):
        if args.debug:
            print ">>> reading from chunk ptr %02x" % ptrChunkType

        chunk_type = data[ptrChunkType]
        chunk_len = data[ptrChunkLen] * 256 + data[ptrChunkLen + 1]
        # if chunk_len is not multiple of 4 there are padding bytes
        # and we need to skip over them
        if chunk_len % 4 != 0:
            add_len = 4 - (chunk_len % 4)
            chunk_len = chunk_len + add_len

        if args.debug:
            print "> packet %d: sctp data length=%d" %(npackets, chunk_len)

        # append chunk to packet
        repack = repack + data[ptrChunkType : ptrChunkType + chunk_len]

        # zero the sctp checksum field and calculate the checksum
        repack[ptrSctpChecksum:ptrSctpChecksum + 4] = [0] * 4
        cksum = protocols.sctp.crc32c(repack[ptrSctp:ptrSctp + chunk_len + 12])
        repack[ptrSctpChecksum:ptrSctpChecksum + 4] = cksum

        # calculate ip len...
        iplen = len(repack) - ptrIp
        repack[ptrIpLen] = int(iplen / 256)
        repack[ptrIpLen + 1] = iplen % 256

        # calculate ip header checksum and insert into packet
        csum = protocols.ip.checksum(repack[ptrIp:ptrIp + 20])
        repack[ptrIpChecksum] = int(csum / 256)
        repack[ptrIpChecksum + 1] = csum % 256

        # calculate new values of incl_len and orig_len and write packet
        newlen = len(repack)
        write_packet(recap, endian, ts_sec, ts_usec, newlen, newlen, repack)

        # clear sctp payload
        repack[ptrSctpPayload:] = []

        # point to next chunk
        ptrChunkType = ptrChunkType + chunk_len
        ptrChunkLen = ptrChunkType + 2

    ptr = next_packet
    npackets = npackets + 1

