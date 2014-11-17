/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gimme-bitcoin-address
 * MIT Licensed
 */

package btcaddr

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"crypto/sha256"
	"code.google.com/p/go.crypto/ripemd160"
)

/******************************************************************************/
/* Bitcoin Keypair Generation */
/******************************************************************************/

/* We make our own Bitcoin Private Key and Public Key structs here so no one
 * tries to use this code with crypto/ecdsa, which doesn't support the
 * secp256k1 elliptic curve that bitcoin uses */

// BitcoinPrivateKey represents a private key
type BitcoinPrivateKey struct {
	D *big.Int
}

// BitcoinPublicKey represents a private key
type BitcoinPublicKey struct {
	X, Y *big.Int
}

// GenerateKeyPair generates a private and public key pair
func GenerateKeyPair() (prikey BitcoinPrivateKey, pubkey BitcoinPublicKey, err error) {
	/* See SEC2 pg.9 http://www.secg.org/collateral/sec2_final.pdf */

	/* secp256k1 elliptic curve parameters */
	var curve = &EllipticCurve{}
	curve.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	curve.A, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	curve.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	curve.G.X, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	curve.G.Y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	curve.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	curve.H, _ = new(big.Int).SetString("01", 16)

	/* See SEC1 pg.23 http://www.secg.org/collateral/sec1_final.pdf */

	/* Select private key d randomly from [1, n) */
	/* Random integer uniformly selected from [0, n-1) range */
	d, err := rand.Int(rand.Reader, new(big.Int).Sub(curve.N, big.NewInt(1)))
	if err != nil {
		return prikey, pubkey, fmt.Errorf("Error: generating random private key.")
	}
	/* Add one to shift d to [1, n) range */
	d.Add(d, big.NewInt(1))

	/* Derive public key from Q = d*G */
	Q := curve.pointScalarMultiply(d, curve.G)

	/* Check that Q is on the curve */
	if !curve.isOnCurve(Q) {
		return prikey, pubkey, fmt.Errorf("Error: catastrophic math logic failure.")
	}

	prikey.D = d
	pubkey.X = Q.X
	pubkey.Y = Q.Y

	return prikey, pubkey, nil
}

/******************************************************************************/
/* Bitcoin Public and Private Key Export Mechanics */
/******************************************************************************/

// Base58 computes the base-58 encoding of a bytes sequence b.
func Base58(b []byte) (s string) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Initialize */
	x := new(big.Int).SetBytes(b)
	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	s = ""

	/* While x > 0 */
	for x.Cmp(zero) > 0 {
		/* x, r = (x / 58, x % 58) */
		x.QuoRem(x, m, r)
		/* Prepend ASCII character */
		s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
	}

	/* For number of leading 0's in bytes, prepend 1 */
	for _, v := range b {
		if v != 0 {
			break
		}
		s = string(BITCOIN_BASE58_TABLE[0]) + s
	}

	return s
}

// ToWIF converts a Bitcoin private key to a Wallet Import Format string.
func (prikey *BitcoinPrivateKey) ToWIF() (wif string) {
	/* See https://en.bitcoin.it/wiki/Wallet_import_format */

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* Convert the private key to a byte sequence */
	prikey_bytes := prikey.D.Bytes()

	/* 1. Prepend 0x80 */
	wif_bytes := append([]byte{0x80}, prikey_bytes...)

	/* 2. SHA256 Hash */
	sha256_h.Reset()
	sha256_h.Write(wif_bytes)
	prikey_hash_1 := sha256_h.Sum(nil)

	/* 3. SHA256 Hash */
	sha256_h.Reset()
	sha256_h.Write(prikey_hash_1)
	prikey_hash_2 := sha256_h.Sum(nil)

	/* 4. Checksum is first 4 bytes of second hash */
	checksum := prikey_hash_2[0:4]

	/* 5. Append the checksum */
	wif_bytes = append(wif_bytes, checksum...)

	/* 6. Base58 the byte sequence */
	wif = Base58(wif_bytes)

	return wif
}

// ToAddress converts a Bitcoin public key to a Bitcoin address string.
func (pubkey *BitcoinPublicKey) ToAddress(version uint8) (address string) {
	/* See https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses */

	/* Create a new SHA256 context */
	sha256_h := sha256.New()
	/* Create a new RIPEMD160 Context */
	ripemd160_h := ripemd160.New()

	/* Convert the public key to a byte sequence */
	pubkey_bytes := pubkey.X.Bytes()
	pubkey_bytes = append(pubkey_bytes, pubkey.Y.Bytes()...)

	/* 1. Prepend 0x04 */
	pubkey_bytes = append([]byte{0x04}, pubkey_bytes...)

	/* 2. SHA256 Hash */
	sha256_h.Reset()
	sha256_h.Write(pubkey_bytes)
	pubkey_hash_1 := sha256_h.Sum(nil)

	/* 3. RIPEMD-160 Hash */
	ripemd160_h.Reset()
	ripemd160_h.Write(pubkey_hash_1)
	pubkey_hash_2 := ripemd160_h.Sum(nil)

	/* Prepend version byte */
	pubkey_hash_2 = append([]byte{version}, pubkey_hash_2...)

	/* 4. SHA256 Hash */
	sha256_h.Reset()
	sha256_h.Write(pubkey_hash_2)
	pubkey_hash_3 := sha256_h.Sum(nil)

	/* 5. SHA256 Hash */
	sha256_h.Reset()
	sha256_h.Write(pubkey_hash_3)
	pubkey_hash_4 := sha256_h.Sum(nil)

	/* 6. Checksum is first 4 bytes of previous hash */
	checksum := pubkey_hash_4[0:4]

	/* 7. Add checksum to extended RIPEMD-160 hash */
	address_bytes := append(pubkey_hash_2, checksum...)

	/* 8. Base58 the byte sequence */
	address = Base58(address_bytes)

	return address
}
