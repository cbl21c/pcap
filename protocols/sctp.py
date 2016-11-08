#!/usr/bin/python

# chunk types (RFC2960)
DATA			= 0
INIT			= 1
INIT_ACK		= 2
SACK			= 3
HEARTBEAT		= 4
HEARTBEAT_ACK		= 5
ABORT			= 6
SHUTDOWN		= 7
SHUTDOWN_ACK		= 8
ERROR			= 9
COOKIE_ECHO		= 10
COOKIE_ACK		= 11
ECNE			= 12
CWR			= 13
SHUTDOWN_COMPLETE	= 14


#
# this is the global crc lookup table
# compute this the first time that crc32c() is called
# subsequent calls will not need to rebuild
#
crc32table = None


#########################################
#                                       #
#  reflect(x, width)                    #
#                                       #
#  function to reflect a single integer #
#  where the size (width) can be passed #
#  as a parameter                       #
#                                       #
#########################################

def reflect(x, width):
    wbytes = int(width / 8)
    wmask = 0
    for n in range(wbytes):
        wmask = (wmask << 8) + 0xff

    x = x & wmask
    ref = 0
    for n in range(width):
        ref = (ref << 1) + (x % 2)
        x = x >> 1

    return ref


########################################
#                                      #
#  reflect_bytes(S)                    #
#                                      #
#  function to reflect the byte values #
#  in a series of bytes                #
#  (could be a single byte)            #
#                                      #
########################################

def reflect_bytes(S):
    # S is either an integer or a list of bytes

    ref = 0

    if (type(S) is int):
        s = S

        for j in range(8):
            ref = (ref << 1) + s % 2
            s = s >> 1

        return ref

    elif (type(S) is list):
        M = []

        for i in range(len(S)):
            # check that each element in S is an int
            s = S[i]
            if (type(s) is not int):
                return None

            ref = 0
            for j in range(8):
                ref = (ref << 1) + s % 2
                s = s >> 1

            M.append(ref)

        return M

    # invalid types will fall through there
    return None


###########################################
#                                         #
#  crcLookupTable(poly, width)            #
#                                         #
#  function to calculate mask values      #
#  for a table driven algorithm           #
#                                         #
###########################################

def crcLookupTable(poly, width):
    wbytes = width / 8

    # calculate a mask to restrict the values to width bits
    wmask = 0
    for n in range(wbytes):
        wmask = (wmask << 8) + 0xff

    # AND the poly just in case it runs over width bits
    poly = poly & wmask

    # initialise the lookup table
    lookup = [None] * 256

    # mask value for 0x00 is always 0x00
    lookup[0] = 0x00

    for control in range(256):
        # skip this control value if mask has already been calculated
        if lookup[control] >= 0:
            continue

        # load the top byte of register with the control value
        reg = control << (width - 8)

        # store[i] holds the control value at iteration i-8
        # this allows us to calculate the mask value at the end
        # clear the store before each calculation chain
        store = [None] * 8

        iter = 0
        done = False
        endOfChain = 8
        numDone = 0

        while iter <= endOfChain:
            if store[iter] is not None:
                # we now have the mask for the control value 8 iterations ago
                index = store[iter] >> (width - 8)
                operand = (store[iter] << 8) & wmask
                mask = operand ^ reg
                lookup[index] = mask

            index = reg >> (width - 8)

            if (lookup[index] is None) and (not done):
                # mask has not yet been calculated for current control value
                # enter the control value in store and advance the endOfChain
                store.append(reg)
                endOfChain = iter + 8

                # use value -1 to identify control values that are in the pipeline
                lookup[index] = -1
            else:
                # mask value has been calculated or is in the pipeline
                store.append(None)
                done = True

            # the simple algorithm... shift and xor
            hibit = reg >> (width - 1)
            reg = (reg << 1) & wmask

            if hibit == 1:
                reg = reg ^ poly

            # next iteration
            iter = iter + 1

    return lookup


#########################################################
#                                                       #
#  crc32c(msg)                                          #
#                                                       #
#  computes the crc32c checksum for a given msg         #
#  follows the optimised table algorithm in WILLIAMS93  #
#                                                       #
#  poly     = 0x1EDC6F41                                #
#  width    = 32                                        #
#  init     = 0xffffffff                                #
#  refin    = True                                      #
#  refout   = True                                      #
#  xorout   = 0xffffffff                                #
#                                                       #
#########################################################

def crc32c(msg):

    global crc32table

    poly     = 0x1EDC6F41
    width    = 32
    init     = 0xffffffff
    refin    = True
    refout   = True
    xorout   = 0xffffffff

    wbytes = int(width / 8)

    # check if we need to reflect the data bytes
    if refin:
        msg = reflect_bytes(msg)

    # calculate a mask to restrict the values to width bits
    wmask = 0
    for n in range(wbytes):
        wmask = (wmask << 8) + 0xff

    # AND the poly just in case it runs over width bits
    poly = poly & wmask

    # first time this is called so generate the lookup table
    if crc32table is None:
        crc32table = crcLookupTable(poly, width)
        if crc32table is None:
            return 0x00000000

    reg = init
    mlen = len(msg)

    for n in range(mlen):
        # print "%04x" % reg
        hireg = reg >> (width - 8)

        reg = (reg << 8) & wmask
        index = hireg ^ msg[0]
        mask = crc32table[index]

        msg.pop(0)
        reg = reg ^ mask

    # check if we need to reflect the checksum
    if refout:
        reg = reflect(reg, width)

    reg = reg ^ xorout

    # need to swap the byte order
    bytelist = []
    for n in range(wbytes):
        bytelist.append(reg & 0xff)
        reg = reg >> 8

    return bytelist


