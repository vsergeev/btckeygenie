# gobtcaddr v1.0

gobtcaddr is a standalone Bitcoin address generator written in Go. gobtcaddr
generates an ECDSA secp256k1 keypair, dumps the public key in compressed and
uncompressed Bitcoin address, hexadecimal, and base64 formats, and dumps the
private key in Wallet Import Format (WIF), Wallet Import Format Compressed
(WIFC), hexadecimal, and base64 formats.

gobtcaddr includes a lightweight package called btckey to easily generate
keypairs, and convert them between compressed and uncompressed varieties of
Bitcoin Address, Wallet Import Format, and raw bytes.

See documentation on btckey here: https://godoc.org/github.com/vsergeev/gobtcaddr/btckey

Donations are welcome at `15PKyTs3jJ3Nyf3i6R7D9tfGCY1ZbtqWdv` :)

## Usage

    $ gobtcaddr
    Bitcoin Address (Compressed)        14ySRLDc1Dqaj9i36eLnryMKGZ8yHqByyz
    Public Key Bytes (Compressed)       0390CCFDBAA54A83298B0E39764D9D44A4272B64E9F912A8E03A5D16A452C8B08E
    Public Key Base64 (Compressed)      A5DM/bqlSoMpiw45dk2dRKQnK2Tp+RKo4DpdFqRSyLCO
    
    Bitcoin Address (Uncompressed)      1DQa4MnxBcUzFRjNN56bvWj7BhqnfzqDjH
    Public Key Bytes (Uncompressed)     0490CCFDBAA54A83298B0E39764D9D44A4272B64E9F912A8E03A5D16A452C8B08
                                        E4E081D4FFCFB3655B49892C413BA708B05382B528ECF6B8DA91ACEB40D745279
    Public Key Base64 (Uncompressed)    BJDM/bqlSoMpiw45dk2dRKQnK2Tp+RKo4DpdFqRSyLCOTggdT/z7NlW0mJLEE7pwiwU4K1KOz2uNqRrOtA10Unk=
    
    Private Key WIFC (Compressed)       KzLYa9EcrX5zNyTqiRV4DpfrGXhxaonfkWFHZX1tziWT3FAAYyy6
    Private Key WIF (Uncompressed)      5JXFrefRtYjpSNQJP5BtUpxUUXyQU9LQjUvXwVYvU892peFmeJg
    Private Key Bytes                   5D072AD27A65B0210718AB1852E8C3BD4054523FE327FDEFF070AD13F6758DBA
    Private Key Base64                  XQcq0nplsCEHGKsYUujDvUBUUj/jJ/3v8HCtE/Z1jbo=
    $

## Building

    $ go install github.com/vsergeev/gobtcaddr

## Issues

Feel free to report any issues, bug reports, or suggestions at github or by
email at vsergeev at gmail.

## License

gobtcaddr is MIT licensed. See the included `LICENSE` file for more details.

