#!/usr/bin/python3

import argparse
from Crypto.Cipher import AES
from Crypto.Hash import SHA384, SHA256

from binascii import unhexlify
from Crypto.Util.Padding import unpad, pad

import binascii

"""
Figuring out the bitstream encryption format.

Let's assume we are working with a .bin format, which
lacks the informative header on the .bit file (and is the
type that is burned into the ROM anyways).

# The basic bit swizzle

The ciphertext starts at byte 184. To decrypt:

* bit-reverse each byte ([7:0] -> [0:7] on each byte)
* byte-reverse each 32-bit word ([ABCD] -> [DCBA])
* feed into AES

So, to encrypt:
* feed bitstream into AES
* byte-reverse each 32-bit word
* bit reverse each byte

This is validate with key=0, IV=0.

# The HMAC

The HMAC key is written into the bitstream as follows:

Two copies of the HMAC key are stored, once in the header, once in the footer.

Prepare the header:

* byte-reverse each 32-bit word of the HMAC key
* bit-reverse each byte
* XOR each byte with 0x6C
* pad an additional 32 bytes of 0x6C
* pre-pend to bitstream

Total header length is 64 bytes.

Prepare the footer:

* byte-reverse each 32-bit word of the HMAC key
* bit-reverse each byte
* XOR each byte with 0x3A
* pad an additional 32 bytes of 0x3A
* append the following 64 bytes:

0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
0000 0001 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 00c0 0000

At this point, it looks like an HMAC that is a SHA-256 hash is appended to
the message. However, we have not been able to get a computed hash to line 
up with the decrypted value output at the bottom of the file, so there
is likely some additional trick to how the decrypted bitstream is fed into
the HMAC algorithm. 
 
Once prepared, this entire set is encrypted using AES-CBC.

Note that the number 0x085b98 is immediately before the cipherext data (this is for
the 35T), and this corresponds to 547,736 words or 2,190,944 bytes, which corresponds
exactly to a 32-byte SHA-256 digest appended to the end of the entire stream including
header and footer (including the extra weird 64 bytes at the end), that is, 2190912 bytes. 

An extra 16-bytes of random-looking data appears after this length when you 
"over-decrypt" because the repeating output of the CBC cipher doesn't start until 
one block after the last block.


Todo:
* Figure out key byte order (mapping of eFuse bit order-to-AES)
* Figure out IV byte order (presume it also has same bit re-ordering rules, but check)
* Figure out how the SHA-256 HMAC is applied to the bitstream.

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


def hmac_format(data_block):
    # swap all bits MSB-to-LSB in an 8-bit block
    #bitswapped = bytearray()
    #for byte in data_block:
        # print(format(byte, '02x'))
    #    bitswapped.extend(int('{:08b}'.format(byte)[::-1], 2).to_bytes(1, byteorder='big'))

    #return bytes(bitswapped)

    bitswapped = data_block
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

    ### reconstrution of the plaintext header
    hmac = int(1).to_bytes(32, byteorder='big')
    print("hmac: ", binascii.hexlify((hmac)))
    hmac_swizzle = xilinx_swizzle(hmac)
    print("hmac_swizzle: ", binascii.hexlify((hmac_swizzle)))

    scramble_header = int(0x6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C).to_bytes(32, byteorder='big')
    print("scramble: ", binascii.hexlify((scramble_header)))
    header = bytearray()
    for i in range(0, 32):
        header.extend((hmac_swizzle[i] ^ scramble_header[i]).to_bytes(1, byteorder='big'))
    header = bytes(header)
    print("hmac_header: ", binascii.hexlify(header))

    scramble_footer = int(0x3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A).to_bytes(32, byteorder='big')
    print("scramble: ", binascii.hexlify((scramble_footer)))
    footer = bytearray()
    for i in range(0, 32):
        footer.extend((hmac_swizzle[i] ^ scramble_footer[i]).to_bytes(1, byteorder='big'))

    footer = bytes(footer)
    print("hmac_footer: ", binascii.hexlify(footer))


    ### figuring out the HMAC.
    # this is the plaintext number appended to the bitstream for a MAC key of "1"
    big_hmac = int(0xfc59d3235884391b0ec66b850e668087273368153ec3d8ef68b25fbcaf7547ed).to_bytes(32, byteorder='big')
    print("big_hmac: ", binascii.hexlify((big_hmac)))
    print("big_hmac_swizzle: ", binascii.hexlify(xilinx_swizzle(big_hmac)))
    big_hmac = int(0xFDAC4413D5A6FAEF517088C5549A4B752A2C6C1D8F32561EA6060F529EBA2CEF).to_bytes(32, byteorder='big')
    print("big_hmac_cipher: ", binascii.hexlify((big_hmac)))
    print("big_hmac_cipher_swizzle: ", binascii.hexlify(xilinx_swizzle(big_hmac)))

    # note that the input length is exactly a multiple of 64 bytes or 512 bits
    # which means there is no need to pad the last block of the SHA-256 message
    with open("decrypt-hmac1-t1.bin", 'rb') as hfile:
        msg = hfile.read()
        if (len(msg) % 64) != 0:
            print("Note: file being tried is not an even block length size")
        h = SHA256.new()
        as_blocks = False  # convinced myself that block-lengths updates don't matter (as they shouldn't)
        if as_blocks:
            k = 0
            while k < len(msg) - 128: #just trying to see what happens if we lop off some of the trailing gunk
                h.update(msg[k:k+16])
                k = k + 16
        else:
            h.update(hmac_format(msg))
        digest = h.digest()
        print("digest: ", binascii.hexlify(digest))
        print("digest_swizzle: ", binascii.hexlify(xilinx_swizzle(digest)))
    # this is the ciphertext version of the hash -- just in case they didn't try to encrypt it??
    # 0xFDAC4413D5A6FAEF517088C5549A4B752A2C6C1D8F32561EA6060F529EBA2CEF

    exit(0)

    ### figuring out the AES bit order
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