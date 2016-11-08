# Pcap Utilities
This repository contains Python classes for handling pcap and pcapng files,
modules for handling network protocols, and miscellaneous utilities.

<h3>pcap.py</h3>
Defines classes PcapFile and PcapRecord:

<pre>
class PcapRecord:
    __init__(ts_sec=0, ts_usec=0, incl_len=0, orig_len=0, data=None)

class PcapFile:
    __init__(filename=None)
    read()
    writeto(fname)
    delete(x)
    swap(a, b)
    relocate(a, b)
</pre>


<h3>pcapng.py</h3>
Defines classes PcapngFile and the block headers:

<pre>
class SectionHeaderBlock:
    __init__(endian='@', byteData=None)
    dump()

class InterfaceDescriptionBlock:
    __init__(endian='@', byteData=None)
    dump()

class EnhancedPacketBlock:
    __init__(endian='@', byteData=None)
    dump()

class PcapFile:
    __init__(filename=None)
    read()
</pre>


<h3>sctpdebundle.py</h3>
Debundles SCTP chunks within a packet and writes each chunk in its own packet in a new
pcap file. Non-SCTP packets are written to the pcap file unmodified.


<h3>protocols/ethernet</h3>
Module contains identities for the Ethernet level.


<h3>protocols/ip</h3>
Module contains identities and functions for the IP level. The function checksum()
calculates the IP header checksum.


<h3>protocols/sctp</h3>
Module contains identities and functions for the SCTP level. The function checksum()
calculates the SCTP CRC32c checksum.

