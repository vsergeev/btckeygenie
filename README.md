gobtcaddr v1.0
==============

gobtcaddr is a standalone Bitcoin address generator written in Go. gobtcaddr
generates an ECDSA secp256k1 keypair, prints the public key in Bitcoin Address
format, and prints the private key in Wallet Import Format.

gobtcaddr includes a lightweight package "btckey" to easily generate keypairs,
and convert them to Bitcoin Address format and Wallet Import Format.

gobtcaddr is MIT licensed. See the provided LICENSE file.

Donations are welcome at `15PKyTs3jJ3Nyf3i6R7D9tfGCY1ZbtqWdv` :)

Feel free to report any issues, bug reports, or suggestions at github or by
email at vsergeev at gmail.

Example
-------

    $ ./gobtcaddr
    Address: 1LD4UXR9bhWCdbpDQiExv88D53275fSH1R
        WIF: 5JEbJAuksPuB9BVgMfQxiULYzAtps6un6E2tPqxVKXidiQp11Y1
    $

Building
--------

    $ go install github.com/vsergeev/gobtcaddr

Important Note
--------------

I had to implement elliptic curve operations and ECDSA key generation from
scratch for Bitcoin's curve, secp256k1, because golang's crypto/elliptic only
supports curves with a=-3.  While I am not worried about its ability to
generate validate Bitcoin keypairs, it may be vulnerable to timing attacks
during the public key computation. Use at your own risk in a public facing
setting (e.g. web). If you have some experience or thoughts on this matter,
please let me know.

