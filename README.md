# encrypt-bitstream-python

This utility takes a bitstream that has previously been encrypted with
Xilinx vendor tools using a dummy key, and re-encrypts it to a key
specified in a key file.

The reason we start with a bitfile encrypted with a dummy key is that
it comes with all the additional formatting and commands to control
and set up the encryption machinery in the 7-series device. If we
started from a plaintext file, a heavier edit would be required of the
bitstream.

This utility allows the key to be generated and stored in a secured
location with an inspectable program, without having to rely upon
an opaque vendor tool to encrypt the bitstream. This can be paired
with the JTAG efuse burning API found at
https://github.com/betrusted-io/betrusted-soc/tree/master/sw/efuse-api
to create an end-to-end solution for creating and managing keys using
only code that can be inspected for correctness.

## Contribution Guidelines

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

Please see [CONTRIBUTING](CONTRIBUTING.md) for details on
how to make a contribution.

Please note that this project is released with a
[Contributor Code of Conduct](CODE_OF_CONDUCT.md).
By participating in this project you agree to abide its terms.

## License

Copyright © 2020

Licensed under the [GPL-3.0](https://opensource.org/licenses/GPL-3.0) [LICENSE](LICENSE)
