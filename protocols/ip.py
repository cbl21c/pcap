#!/usr/bin/python

# Assigned Internet Protocol Numbers (RFC0790)
ICMP			= 1
GATEWAY2GATEWAY		= 3
CMCC_GATEWAY		= 4
ST			= 5
TCP			= 6
UCL			= 7
SECURE			= 9
BBN_RCC			= 10
NVP			= 11
PUP			= 12
PLURIBUS		= 13
TELENET			= 14
XNET			= 15
CHAOS			= 16
UDP			= 17
MULTIPLEX		= 18
DCN			= 19
TAC			= 20
SATNET_EXPAK		= 64
MIT_SUBNET		= 65
SATNET_MONITOR		= 69
PACKET_CORE		= 71
BACKROOM_SATNET		= 76
WIDEBAND_MONITOR	= 78
WIDEBAND_EXPAK		= 79
SCTP			= 132


#
# checksum(packet) calculates the IP checksum for the given header data
# minimum header length is 20 bytes; any extra bytes are ignored
# the checksum field itself is zeroed before calculation
#
def checksum(packet):
    # determine the ip header length (in multiples of 32-bit words)
    ihl = packet[0] & 0x0f

    # zero the checksum field: at offsets 0x0a, 0x0b
    packet[10:12] = [0, 0]

    word = 0
    for byte in packet[0:ihl * 4:2]:
        word = word + byte * 256

    for byte in packet[1:ihl * 4:2]:
        word = word + byte

    hi = int(word / 65536)
    lo = word % 65536

    sum = lo + hi
    csum = sum ^ 0xffff

    return csum

