gimme-bitcoin-address
=====================

gimme-bitcoin-address is a standalone Bitcoin address generator written in Go.
It generates an ECDSA secp256k1 keypair, writes the private key in **Wallet
Import Format** to a text file to directory specified with the first argument,
and writes the corresponding public key in **Bitcoin Address** format to
standard output.

gimme-bitcoin-address is intended to be a lightweight tool to generate
one-time-use Bitcoin Addresses.

**Important Note:** I had to implement elliptic curve operations and ECDSA key
generation manually for secp256k1, because golang's crypto/elliptic only
supports curves with a=-3. While I am not worried about its ability to generate
validate bitcoin keypairs, it may be vulnerable to timing attacks during the
public key computation. Use at your own risk in a public facing setting (e.g.
web). If you have some experience or thoughts on this matter, please let me
know.

gimme-bitcoin-address is MIT licensed. See the provided LICENSE file.

Donations are welcome at `15PKyTs3jJ3Nyf3i6R7D9tfGCY1ZbtqWdv` :)

Feel free to report any issues, bug reports, or suggestions at github or by
email at vsergeev at gmail.

Example
-------

    $ ./gimme-bitcoin-address keys/
    1LVFsHMZ98WfHsGZqkcYEvkbomiHFAXEre
    $ ls keys/
    2013-05-08_1367987627405535424_26643.txt
    $ more keys/2013-05-08_1367987627405535424_26643.txt
    5J1d4qtVDX34k6CLcVdi3s8BNRZybFqQb34BtqHNwjxmS1JWb5n
    $

Full Usage
----------

    $ ./gimme-bitcoin-address
    Usage: ./gimme-bitcoin-address <private key directory path> [label]

    Version 1.0 | https://github.com/vsergeev/gimme-bitcoin-address
    $

Private Key Filename Format
---------------------------

    YYYY-MM-DD_UnixTimestamp_PID_<optional label>.txt

Building
--------

    $ git clone git://github.com/vsergeev/gimme-bitcoin-address.git
    $ cd gimme-bitcoin-address
    $ go get code.google.com/p/go.crypto/ripemd160
    $ go build

