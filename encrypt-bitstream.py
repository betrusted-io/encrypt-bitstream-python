#!/usr/bin/python3

import argparse
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

import binascii
import logging
import sys

"""
Encrypting a 7-series bitstream.

Encrypted bitstreams have a slightly different structure than
normal bitstreams, so to simplify things, we start from a bitstream
that is "encrypted" with a dummy key. We then decrypt this stream
and re-encrypt it to the key of choice; by doing this, we can just
update the file with minimal editing. 

We working with a .bin format, which lacks the informative header 
on the .bit file (and is the type that is burned into the ROM anyways).

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

# This is a fixed header for the bitstream, contains sync patterns and configures options such
# as the bitwidth of the config, voltage, etc. This one configures 66MHz config speed, x1, 1.8V
# Making a static copy of this header because it contains commands that modify the operation
# of the FPGA; if we just copy from the incoming bitstream, an attacker may be able to manipulate the
# setup commands in a way that can affect the encryption settings.
bitstream_header_x1 = [
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0x00, 0x00, 0x00, 0xbb, 0x11, 0x22, 0x00, 0x44, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xaa, 0x99, 0x55, 0x66, 0x20, 0x00, 0x00, 0x00, 0x30, 0x03, 0xe0, 0x01, 0x00, 0x00, 0x00, 0x0b,
0x30, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x12, 0x20, 0x00, 0x00, 0x00, 0x30, 0x00, 0xc0, 0x01,
0x80, 0x00, 0x00, 0x40, 0x30, 0x00, 0xa0, 0x01, 0x80, 0x00, 0x00, 0x40, 0x30, 0x01, 0xc0, 0x01,
0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30, 0x01, 0x60, 0x04,
]
# this one selects 66MHz config speed, x2, 1.8V, encryption on, with key from efuse
bitstream_header_x2 = [
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0x00, 0x00, 0x00, 0xbb, 0x11, 0x22, 0x00, 0x44, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xaa, 0x99, 0x55, 0x66, 0x20, 0x00, 0x00, 0x00, 0x30, 0x03, 0xe0, 0x01, 0x00, 0x00, 0x01, 0x3b,
0x30, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x12, 0x20, 0x00, 0x00, 0x00, 0x30, 0x00, 0xc0, 0x01,
0x80, 0x00, 0x00, 0x40, 0x30, 0x00, 0xa0, 0x01, 0x80, 0x00, 0x00, 0x40, 0x30, 0x01, 0xc0, 0x01,
0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30, 0x01, 0x60, 0x04,
]
# then IV key is here 16 bytes
ciphertext_header = [
0x30, 0x03, 0x40, 0x01, 0x00, 0x08, 0x5b, 0x98,
]

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

# assumes a, b are the same length eh?
def xor_bytes(a, b):
    i = 0
    y = bytearray()
    while i < len(a):
        y.extend((a[i] ^ b[i]).to_bytes(1, byteorder='little'))
        i = i + 1

    return bytes(y)

def patcher(bit_in, patch):
    bitstream = bit_in[64:-160]

    if len(patch) > 0:
        # find beginning of type2 area
        position = 0
        type = -1
        command = 0
        while type != 2:
            command = int.from_bytes(bitflip(bitstream[position:position+4]), byteorder='big')
            position = position + 4
            if (command & 0xE0000000) == 0x20000000:
                type = 1
            elif (command & 0xE0000000) == 0x40000000:
                type = 2
            else:
                type = -1
        count = 0x3ffffff & command  # not used, but handy to have around

        ostream = bytearray(bitstream)
        # position now sits at the top of the type2 region
        # apply patches to each frame specified, ignoring the "none" values
        for line in patch:
            d = line[1]
            for index in range(len(d)):
                if d[index].strip() != 'none':
                    data = bitflip(int(d[index],16).to_bytes(4, 'big'))
                    frame_num = int(line[0],16)
                    for b in range(4):
                        stream_pos = position + frame_num * 101 * 4 + index * 4 + b
                        ostream[stream_pos] = data[b]

        return bytes(ostream)
    else:
        return bitstream

def dumpframes(ofile, framestream):
    position = 0
    type = -1

    command = 0
    while type != 2:
        command = int.from_bytes(framestream[position:position+4], byteorder='big')
        position = position + 4
        if (command & 0xE0000000) == 0x20000000:
            type = 1
        elif (command & 0xE0000000) == 0x40000000:
            type = 2
        else:
            type = -1
    count = 0x3ffffff & command
    end = position + count
    framecount = 0

    while position < end:
        ofile.write('0x{:08x},'.format(framecount))
        framecount = framecount + 1
        for i in range(101):
            command = int.from_bytes(framestream[position:position + 4], byteorder='big')
            position = position + 4
            ofile.write(' 0x{:08x},'.format(command))
        ofile.write('\n')


def main():
    parser = argparse.ArgumentParser(description="Re-encrypt 7-series bitstream with a new key")
    parser.add_argument(
        "-f", "--file", required=True, help="Root filename for input file. Should be a .bin (not .bit)", type=str
    )
    parser.add_argument(
        "-i", "--input-key", required=True, help="Root name for the input file key. Uses .nky format.", type=str
    )
    parser.add_argument(
        "-k", "--key", required=True, help="Root filename of new key to encrypt to. Uses .nky format.", type=str
    )
    parser.add_argument(
        "-o", "--output-file", help="output filename root. Generates .bin and .nky files", type=str
    )
    parser.add_argument(
        "-d", "--debug", help="turn on debugging spew", default=False, action="store_true"
    )
    parser.add_argument(
        "-a", "--ascii-frame-file", help="dump ascii frames to this file", type=str
    )
    parser.add_argument(
        "-p", "--patch", help="file containing patch frames, as output by key2bits.py", type=str
    )
    parser.add_argument(
        "-j", "--jtag-commands", help="Make JTAG command sequence for BBRAM programming via jtag-gpio.py", default=False, action="store_true"
    )
    args = parser.parse_args()

    ifile = args.file
    ofile = args.output_file
    keyfile = args.key
    framefile = args.ascii_frame_file

    if args.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    patch = []
    if args.patch != None:
        patchfile = args.patch
        with open(patchfile, "r") as pf:
            for lines in pf:
              line = lines.split(',')
              patch += [[line[0], line[1:]]]
            # note: patches must be ordered by frame offset

    # extract the original key, HMAC, and IV
    with open(args.input_key, "r") as nky:
        for lines in nky:
            line = lines.split(' ')
            if line[1] == '0':
                nky_key = line[2].rstrip().rstrip(';')
            if line[1] == 'StartCBC':
                nky_iv = line[2].rstrip().rstrip(';')
            if line[1] == 'HMAC':
                nky_hmac = line[2].rstrip().rstrip(';')

    logging.debug("original key: %s", nky_key)
    logging.debug("original iv:   %s", nky_iv)
    logging.debug("original hmac: %s", nky_hmac)

    with open(keyfile, "r") as nky:
        for lines in nky:
            line = lines.split(' ')
            if line[1] == '0':
                new_key = line[2].rstrip().rstrip(';')

    # always re-key the IV and HMAC every time the program is run
    new_iv = get_random_bytes(16)
    new_hmac = get_random_bytes(32)

    # format a .nky for the output .bin
    with open(ofile + ".nky", "w") as newkey:
        newkey.write("Device xc7s50;\n")
        newkey.write("Key 0 ")
        newkey.write(new_key)
        newkey.write(";\n")
        newkey.write("Key StartCBC ")
        newkey.write(str(binascii.hexlify(bitflip(new_iv))).strip("b").strip("'"))
        newkey.write(";\n")
        newkey.write("Key HMAC ")
        newkey.write(str(binascii.hexlify(bitflip(new_hmac))).strip("b").strip("'"))
        newkey.write(";\n")

    key_bytes = int(nky_key, 16).to_bytes(32, byteorder='big')
    logging.debug("old key: %s", binascii.hexlify(key_bytes))

    if args.jtag_commands:
        with open(ofile + ".jtg", "w") as jfile:
            jfile.write("ir, 6, 0b010010, program_key\n")
            jfile.write("dr, 32, 0xffffffff\n")
            jfile.write("ir, 6, 0b010001, isc_program\n")
            jfile.write("dr, 32, 0x557b\n")
            for index in range(0, 8):
                jfile.write("ir, 6, 0b010001, isc_program\n")
                jfile.write("dr, 32, 0x{}\n".format(new_key[index*8:(index+1)*8]))
            jfile.write("ir, 6, 0b010101, bbkey_rbk\n")
            jfile.write("dr, 37, 0x1fffffffff\n")
            for index in range(0, 8):
                jfile.write("ir, 6, 0b010101, bbkey_rbk\n")
                jfile.write("dr, 37, 0x1fffffffff\n")

    # open the input file, and recover the plaintext
    with open(ifile, "rb") as f:
        binfile = f.read()

        ciphertext_len = 4* int.from_bytes(binfile[180:184], 'big')
        logging.debug("ciphertext len: %d", ciphertext_len)

        active_area = binfile[184:184 + ciphertext_len]

        iv_bytes = bitflip(binfile[0xa0:0xb0])  # note that the IV is embedded in the file
        logging.debug("recovered iv: %s", binascii.hexlify(iv_bytes))

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        plain_bitstream = cipher.decrypt(bitflip(active_area))

    # now construct the output file and its hashes
    global bitstream_header_x1
    plaintext = bytearray()
    with open(ofile + ".bin", "wb") as f:
        for item in bitstream_header_x1:  # add the cleartext header
            f.write(bytes([item]))

        f.write(bitflip(new_iv)) # insert the IV

        for item in ciphertext_header:  # add the cleartext length-of-ciphertext field before the ciphertext
            f.write(bytes([item]))

        # generate the header and footer hash keys.
        header = int(0x6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C).to_bytes(32, byteorder='big')
        keyed_header = xor_bytes(header, new_hmac)
        footer = int(0x3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A).to_bytes(32, byteorder='big')
        keyed_footer = xor_bytes(footer, new_hmac)

        # add the header
        plaintext.extend(keyed_header)
        plaintext.extend(header)

        # patch the plaintext bitstream, if requested. Also chops the bitstream down to the core size
        # Function chops off last 160 bytes, as there will be re-generated with the new HMAC, and header is skipped
        plain_patched = patcher(plain_bitstream, patch)

        # insert the bitstream plaintext.
        plaintext.extend(plain_patched)

        # compute first HMAC of stream with new HMAC key
        h1 = SHA256.new()
        k = 0
        while k < len(plaintext) - 320:  # HMAC does /not/ cover the whole file, it stops 320 bytes short of the end
            h1.update(bitflip(plaintext[k:k+16], 32))
            k = k + 16
        h1_digest = h1.digest()
        logging.debug("new digest1 (in stored order): %s", binascii.hexlify(bitflip(h1_digest)))

        # add the footer
        plaintext.extend(keyed_footer)
        plaintext.extend(footer)
        plaintext.extend(bytes(32)) # empty spot where hash #1 would be stored
        hash_pad = [ # sha-256 padding for the zero'd hash #1, which is in the bitstream and seems necessary for verification
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00,
        ]
        plaintext.extend(hash_pad)

        # compute the hash of the hash, presumably to prevent length extension attacks?
        h2 = SHA256.new()
        h2.update(bitflip(keyed_footer))
        h2.update(bitflip(footer))
        h2.update(h1_digest)
        h2_digest = h2.digest()

        # commit the final HMAC to the bitstream plaintext
        plaintext.extend(bitflip(h2_digest))
        logging.debug("new digest2: %s", binascii.hexlify(bitflip(h2_digest)))

        # format the new key into the bytes needed by Pycryptodome
        new_key_formatted = int(new_key, 16).to_bytes(32, byteorder='big')
        logging.debug("new key as used: %s", binascii.hexlify(new_key_formatted))
        logging.debug("new iv as used: %s", binascii.hexlify(new_iv))
        # encrypt the bitstream
        newcipher = AES.new(new_key_formatted, AES.MODE_CBC, new_iv)

        # generate the plaintext for debugging if needed
        if args.debug:
            with open("debug.clr", "wb") as dbg:
                dbg.write(bitflip(plaintext))

        # make a frame dump if requested
        if framefile != None:
            with open(framefile, "w") as frameoutput:
                dumpframes(frameoutput, bitflip(plaintext[64:-160])) # strip off hash header and footer before outputting frames

        # finally generate the ciphertext block, which encapsulates the HMACs
        ciphertext = newcipher.encrypt(bytes(plaintext))

        # add ciphertext to the bitstream
        f.write(bitflip(ciphertext))

        # add the cleartext postamble to the bitstream. These are a series of NOP commands to the bitstream engine
        postamble = bytearray([0x20, 00, 00, 00])
        for i in range(0,220):
            f.write(postamble)


if __name__ == "__main__":
    main()