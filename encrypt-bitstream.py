#!/usr/bin/python3

import argparse
from Crypto.Cipher import AES
from Crypto.Hash import SHA384, SHA256

from binascii import unhexlify
from Crypto.Util.Padding import unpad, pad

from math import log2

import binascii

"""
Figuring out the bitstream encryption format.

Let's assume we are working with a .bin format, which
lacks the informative header on the .bit file (and is the
type that is burned into the ROM anyways).

# Decryption

The ciphertext starts at byte 184. To decrypt:

* divide into 32-bit chunks
* reverse the order of the bits in each 32-bit chunk
* feed into AES in big-endian order

So, to encrypt:
* feed bitstream into AES blocks in big-endian order
* reverse the order of bits in each 32-bit chunk
* write out in big endian format. This is referred to "as-stored" format.

This is validate with key=0, IV=0.

# The HMAC

The HMAC key is written into the bitstream as follows:

Two copies of the HMAC key are stored, once in the header, once in the footer.

Prepare the header:

* flip the order of bits in every 32-bit chunk of the HMAC key
* XOR each byte with 0x6C
* pad an additional 32 bytes of 0x6C
* pre-pend to bitstream

Total header length is 64 bytes.

Determine the last command in the bitstream:

This is probably the last instance of "00 00 00 04" in the as-stored bitstream. 
You'll know you found it because when looking at a decrypt bitstream, immediately 
after this you will see a SHA-256 padding (1 followed by many 0's then the 
length of the message; note the order that comes out of AES has to be 
bit-flipped for this pattern to be obvious, when staring at the as-stored bitstream
it's not totally obvious).

The padding looks something like this as-stored:

        v the '1' bit per SHA requirement, but bit-flipped
0000 0001 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0026 d080
                               ^ length of message in bits

Compute hash of the bitstream from the very first byte of the header
to the end of the active bitstream + SHA padding. Call this "hash1". 

Append an additional 256 bytes of 0's after the end of the padding that was
required to compute hash1. 

Now, prepare the footer:

* flip the order of bits in every 32-bit chunk of the HMAC key
* XOR each byte with 0x3A
* pad an additional 32 bytes of 0x3A
* append hash1

Now, compute a hash of the region spanning from the beginning of
the footer (not including the 0 pad, so starting at the 0x3A sequence)
to the end of hash1. This means first padding the region, and then 
computing the hash. 

Bit-flip and append this hash to the overall file, and you have now 
an HMAC-ready bitstream. Note that the Xilinx implementation 0's out
the copy of "hash1" as stored in the bitstream. 
 
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

Bitstream footer notes:

00216d90: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00216da0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00216db0: 0000 0000 0000 0000 0000 0000 0000 0000  ................  <-- end of	FPGA bitstream
00216dc0: 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a  :::::::::::::::: |  | <-- hmac key xor with 0x3a
00216dd0: 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a  :::::::::::::::: |  |
00216de0: 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a  :::::::::::::::: |  |
00216df0: 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a 3a3a  :::::::::::::::: |  |
00216e00: 0000 0000 0000 0000 0000 0000 0000 0000  HMAC1........... |  | <-- where hmac digest #1 was: SHA256(bitstream)
00216e10: 0000 0000 0000 0000 0000 0000 0000 0000  .......was here. |  |____ 96 bytes = 0x300 bits = 0x00C0_0000 bit-reversed
00216e20: 0000 0001 0000 0000 0000 0000 0000 0000  ................ |    <-- padding for hmac digest #1
00216e30: 0000 0000 0000 0000 0000 0000 00c0 0000  ................ |_______ region hashed for hmac digest #2
00216e40: ae61 607f f1ea 2364 5223 bb1b b7b6 069b  .a`...#dR#...... <--	hmac digest #2:	SHA256( (hmackey^0x3a | SHA256(bitstream) | SHA_pad) )
00216e50: 2a48 b7f5 dd28 87e0 e10d 3fd0 66e7 cd15  *H...(....?.f...

For some reason, hmac digest #1	area is	zeroed out after its computation?

"""

"""
Reverse the order of bits in a word that is bitwidth bits wide
"""
def bitflip(data_block, bitwidth=32):
    if bitwidth == 0:
        return data_block

    bytewidth = bitwidth // 8
    bitswapped = bytearray()

    i = 0
    while i < len(data_block):
        data = int.from_bytes(data_block[i:i+bytewidth], byteorder='big', signed=False)
        b = '{:0{width}b}'.format(data, width=bitwidth)
        bitswapped.extend(int(b[::-1], 2).to_bytes(bytewidth, byteorder='big'))
        i = i + bytewidth

    return bytes(bitswapped)

def byteflip(data, bytewidth=4):
    if bytewidth == 0:
        return data

    byteswapped = bytearray()
    i = 0
    while i < len(data):
        b = int.from_bytes(data[i:i+bytewidth], byteorder='big', signed=False)
        byteswapped.extend(b.to_bytes(bytewidth, byteorder='little'))
        i = i + bytewidth

    return bytes(byteswapped)


# assumes a, b are the same length eh?
def xor_bytes(a, b):
    i = 0
    y = bytearray()
    while i < len(a):
        y.extend((a[i] ^ b[i]).to_bytes(1, byteorder='little'))
        i = i + 1

    return bytes(y)


def main():
    parser = argparse.ArgumentParser(description="Encrypt bitstream")
    parser.add_argument(
        "-f", "--file", required=True, help="filename to process", type=str
    )
    parser.add_argument(
        "-o", "--output-file", help="output filename", type=str
    )
    parser.add_argument(
        "-d", "--decrypt", default=False, action='store_true'
    )
    parser.add_argument(
        "-s", "--simulate", default=False, action='store_true', help="Decrypt reference file & simulate hashes"
    )
    args = parser.parse_args()

    ifile = args.file

    if args.decrypt:
        ### figuring out the AES bit order
        for i in range(0, 1):  # wrapped in an iterator, i can be used to brute-force offsets and other parameters
            # initially experimenting with 0-key TODO: figure out key bit order
            key_bytes = bytes(32)
            print("key: ", binascii.hexlify(key_bytes), "length: ", str(len(key_bytes) * 8))

            # initially experimenting with 0-IV TODO: figure out IV bit order
            iv_bytes = bytes(16)
            print("iv: ", binascii.hexlify(iv_bytes))
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            print("block size: ", str(AES.block_size))

            with open(ifile, "rb") as f:
                bitfile = f.read()

            ofilename = args.output_file
            with open(ofilename, "wb") as ofile:

                active_area = bitfile[184 + i:]
                pos = 0

                # to check the first few blocks, change this to pos < 256, and uncomment the prints
                while pos < len(active_area):
                    data_block = active_area[pos:pos + 16]
                    pos = pos + 16

                    db_bytes = bitflip(data_block)

                    # print("ciphertext: ", str(binascii.hexlify(db_bytes)))
                    plain = cipher.decrypt(db_bytes)

                    finalout = bytearray()
                    for b in plain:
                        c = b ^ 0x0  # no actual confounder
                        finalout.extend(c.to_bytes(1, byteorder='little'))

                    # print("plaintext: ", binascii.hexlify(finalout))
                    ofile.write(finalout)

            # function may exit with a padding error, that's OK for now as we haven't yet determined
            # the actual length of the bitstream yet...

    # this subroutine decrypts a 0-key, 0-IV bitstream and then uses the decrypted data to
    # compute the HMAC result from scratch
    elif args.simulate:
        # first setup the key. for now, we use the "0" key, as we haven't figured out the byte
        # ordering for the key format
        key_bytes = bytes(32)
        print("key: ", binascii.hexlify(key_bytes), "length: ", str(len(key_bytes) * 8))

        # also start with the zero IV as that format hasn't been figured out yet
        iv_bytes = bytes(16)
        print("iv: ", binascii.hexlify(iv_bytes))
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

        with open(ifile, "rb") as f:
            binfile = f.read()

            ciphertext_len = 4* int.from_bytes(binfile[180:184], 'big')

            active_area = binfile[184:184 + ciphertext_len]

            plain = cipher.decrypt(bitflip(active_area))

            # now take plain and compute the hashes
            hash_len = ciphertext_len - 0x1E0
            print("hash_len: ", hash_len)
            h1 = SHA256.new()
            k = 0
            while k < hash_len:
                h1.update(bitflip(plain[k:k+16], 32))
                k = k + 16

            print("plain top: ", binascii.hexlify(plain[:64]))
            print("plain bottom: ", binascii.hexlify(plain[hash_len-64:hash_len]))
            h1_digest = h1.digest()

            print("digest1 (in stored order): ", binascii.hexlify(bitflip(h1_digest)))
            print("(this digest is zeroed in the bitstream)")

            h2 = SHA256.new()
            footer = int(0x3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A).to_bytes(32, byteorder='big')
            hmac_key = bitflip(int(1).to_bytes(32, byteorder='big'))
            keyed_footer = xor_bytes(footer, hmac_key)
            print('keyed_footer: ', binascii.hexlify(keyed_footer))
            h2.update(bitflip(keyed_footer))
            print('footer: ', binascii.hexlify(footer))
            h2.update(bitflip(footer))
            print('digest: ', binascii.hexlify(bitflip(h1_digest)))
            h2.update(h1_digest)
            h2_digest = h2.digest()
            print("digest2: ", binascii.hexlify(h2_digest))
            print("final digest2 (in stored order): ", binascii.hexlify(bitflip(h2_digest)))

            print("hmac as found in file (should match above): ", binascii.hexlify(plain[ciphertext_len-32:]))
            exit(0)

    else:
        print("no command specified, exiting")


if __name__ == "__main__":
    main()