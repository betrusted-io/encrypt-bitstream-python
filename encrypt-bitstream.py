#!/usr/bin/python3

import argparse
from Crypto.Cipher import AES

from binascii import unhexlify
from Crypto.Util.Padding import unpad, pad

import binascii

"""
Figuring out the bitstream encryption format.

Let's assume we are working with a .bin format, which
lacks the informative header on the .bit file (and is the
type that is burned into the ROM anyways).

The ciphertext starts at byte 184. To decrypt:

* bit-reverse each byte ([7:0] -> [0:7] on each byte)
* byte-reverse each 32-bit word ([ABCD] -> [DCBA])
* feed into AES

So, to encrypt:
* feed bitstream into AES
* byte-verse each 32-bit word
* bit reverse each byte

This is validate with key=0, IV=0.

Todo:
* Figure out key byte order (mapping of eFuse bit order-to-AES)
* Figure out IV byte order (presume it also has same bit re-ordering rules, but check)
* Figure out HMAC protocol. Docs say SHA-256, but the role of the "HMAC key" as well
  as exactly which regions are hashed and exactly how the hash is stored is unclear.

"""

"""
This is the Xilinx bit-swizzle function
"""
def xilinx_swizzle(data_block):
    # swap all bits MSB-to-LSB in an 8-bit block
    bitswapped = bytearray()
    for byte in data_block:
        # print(format(byte, '02x'))
        bitswapped.extend(int('{:08b}'.format(byte)[::-1], 2).to_bytes(1, byteorder='big'))

    # now swap byte order big endian to little endian within a 32-bit block
    wordswapped = bytearray()
    i = 0
    while i < len(bitswapped):
        word = bitswapped[i:i + 4]
        wordswapped.extend(word[::-1])
        i = i + 4

    return bytes(wordswapped)

"""
Throw-away function used to discover the swizzle above
"""
def long_to_bytes (val, endianness='big', bitswap=False, wordswap=False):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    if bitswap:
        swapped = bytearray()
        for byte in s:
            #print(format(byte, '02x'))
            swapped.extend( int('{:08b}'.format(byte)[::-1], 2).to_bytes(1, byteorder='big') )

        s = swapped

    if wordswap:
        swapped = bytearray()
        i = 0
        while i < len(s):
            word = s[i:i+4]
            swapped.extend(word[::-1])
            i = i+4

        s = swapped

    return s

def main():
    parser = argparse.ArgumentParser(description="Encrypt bitstream")
    parser.add_argument(
        "-f", "--file", required=True, help="filename to process", type=str
    )
    parser.add_argument(
        "-o", "--output-file", required=True, help="output filename", type=str
    )
    args = parser.parse_args()

    ifile = args.file
    ofilename = args.output_file

    for i in range(0, 1): # wrapped in an iterator, i can be used to brute-force offsets and other parameters
        #key = 0xB000000000000000000000000000000000000000000000000000000000000003
        #key_bytes = long_to_bytes(key)
        key_bytes = bytes(32)
        print("key: ", binascii.hexlify(key_bytes), "length: ", str(len(key_bytes) * 8))

        # iv_bytes = long_to_bytes(0x63734739209ac700298ff54ebb01a943)
        #iv_bytes = xilinx_swizzle(long_to_bytes(0x0c7c1ee30b4645469ff7c797d903fab3))
        iv_bytes = bytes(16)
        print("iv: ", binascii.hexlify(iv_bytes))
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        print("block size: ", str(AES.block_size))

        # this is a really simple example that works
        # data_block =  0xd14f37c53d649c6ce3a03cb7886a5d5e
        # print( "ciphertext (before swap): ", format(data_block, '016x'))
        # db_bytes = bytes(long_to_bytes(data_block, 'big', True, True))
        # print("ciphertext: ", str(binascii.hexlify(db_bytes)))
        # plain = cipher.decrypt(db_bytes)
        # print("plaintext: ", binascii.hexlify(plain))

        with open(ifile, "rb") as f:
            bitfile = f.read()

        with open(ofilename, "wb") as ofile:

            active_area = bitfile[184+i:]
            pos = 0

            # to check the first few blocks, change this to pos < 256, and uncomment the prints
            while pos <  len(active_area):
                data_block = active_area[pos:pos+16]
                pos = pos + 16

                db_bytes = xilinx_swizzle(data_block)

                #print("ciphertext: ", str(binascii.hexlify(db_bytes)))
                plain = cipher.decrypt(db_bytes)

                finalout = bytearray()
                for b in plain:
                    c = b ^ 0x0 # no actual confounder
                    finalout.extend(c.to_bytes(1, byteorder='little'))

                #print("plaintext: ", binascii.hexlify(finalout))
                ofile.write(finalout)


        # function may exit with a padding error, that's OK for now as we haven't yet determined
        # the actual length of the bitstream yet...

"""
        with open(ifile, "rb") as f:
            bitfile = f.read()

        active_area = bitfile[184+i:]
        #print("active area:")
        #print(binascii.hexlify((active_area[:128])))
        active_pad = pad(active_area, AES.block_size)

        print("active padded:")
        print(binascii.hexlify((active_pad[:128])))
        plainbit = cipher.decrypt(active_pad)

        print("plainbit:")
        print(binascii.hexlify(plainbit[:128]))
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(plainbit[272:1024])
"""


if __name__ == "__main__":
    main()