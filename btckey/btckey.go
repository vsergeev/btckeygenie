/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gobtcaddr
 * MIT Licensed
 */

package btckey

import (
	"bytes"
	"code.google.com/p/go.crypto/ripemd160"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

/******************************************************************************/
/* Bitcoin Keypair Generation */
/******************************************************************************/

// PublicKey represents a Bitcoin public key.
type PublicKey struct {
	X, Y *big.Int
}

// PrivateKey represents a Bitcoin private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// GenerateKey generates a public and private key pair.
func GenerateKey() (priv PrivateKey, err error) {
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
		return priv, fmt.Errorf("Generating random private key.")
	}
	/* Add one to shift d to [1, n) range */
	d.Add(d, big.NewInt(1))

	/* Derive public key from Q = d*G */
	Q := curve.PointScalarMultiply(d, curve.G)

	/* Check that Q is on the curve */
	if !curve.IsOnCurve(Q) {
		return priv, fmt.Errorf("Catastrophic math logic failure.")
	}

	priv.D = d
	priv.X = Q.X
	priv.Y = Q.Y

	return priv, nil
}

/******************************************************************************/
/* Bitcoin Public and Private Key Export Mechanics */
/******************************************************************************/

// b58encode encodes a bytes slice b into a base-58 encoded string.
func b58encode(b []byte) (s string) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Convert big endian bytes to big int */
	x := new(big.Int).SetBytes(b)

	/* Initialize */
	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	s = ""

	/* Convert big int to string */
	for x.Cmp(zero) > 0 {
		/* x, r = (x / 58, x % 58) */
		x.QuoRem(x, m, r)
		/* Prepend ASCII character */
		s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
	}

	return s
}

// b58decode decodes a base-58 encoded string into a bytes slice b.
func b58decode(s string) (b []byte, err error) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Initialize */
	x := big.NewInt(0)
	m := big.NewInt(58)

	/* Convert string to big int */
	for i := 0; i < len(s); i++ {
		b58index := strings.IndexByte(BITCOIN_BASE58_TABLE, s[i])
		if b58index == -1 {
			return nil, fmt.Errorf("Invalid base-58 character encountered: '%c', index %d.", s[i], i)
		}
		b58value := big.NewInt(int64(b58index))
		x.Mul(x, m)
		x.Add(x, b58value)
	}

	/* Convert big int to big endian bytes */
	b = x.Bytes()

	return b, nil
}

// b58checkencode encodes version ver and bytes slice b into a base-58 check encoded string.
func b58checkencode(ver uint8, b []byte) (s string) {
	/* Prepend version */
	bcpy := append([]byte{ver}, b...)

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* SHA256 Hash #1 */
	sha256_h.Reset()
	sha256_h.Write(bcpy)
	hash1 := sha256_h.Sum(nil)

	/* SHA256 Hash #2 */
	sha256_h.Reset()
	sha256_h.Write(hash1)
	hash2 := sha256_h.Sum(nil)

	/* Append first four bytes of hash */
	bcpy = append(bcpy, hash2[0:4]...)

	/* Encode base58 string */
	s = b58encode(bcpy)

	/* For number of leading 0's in bytes, prepend 1 */
	for _, v := range bcpy {
		if v != 0 {
			break
		}
		s = "1" + s
	}

	return s
}

// b58checkdecode decodes base-58 check encoded string s into a version ver and bytes slice b.
func b58checkdecode(s string) (ver uint8, b []byte, err error) {
	/* Decode base58 string */
	b, err = b58decode(s)
	if err != nil {
		return 0, nil, err
	}

	/* Add leading zero bytes */
	for i := 0; i < len(s); i++ {
		if s[i] != '1' {
			break
		}
		b = append([]byte{0x00}, b...)
	}

	/* Verify checksum */
	if len(b) < 5 {
		return 0, nil, fmt.Errorf("Invalid base-58 check string: missing checksum.")
	}

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* SHA256 Hash #1 */
	sha256_h.Reset()
	sha256_h.Write(b[:len(b)-4])
	hash1 := sha256_h.Sum(nil)

	/* SHA256 Hash #2 */
	sha256_h.Reset()
	sha256_h.Write(hash1)
	hash2 := sha256_h.Sum(nil)

	/* Compare checksum */
	if bytes.Compare(hash2[0:4], b[len(b)-4:]) != 0 {
		return 0, nil, fmt.Errorf("Invalid base-58 check string: invalid checksum.")
	}

	/* Strip checksum bytes */
	b = b[:len(b)-4]

	/* Extract and strip version */
	ver = b[0]
	b = b[1:]

	return ver, b, nil
}

// ToWIF converts a Bitcoin private key to a Wallet Import Format string.
func (priv *PrivateKey) ToWIF() (wif string) {
	/* See https://en.bitcoin.it/wiki/Wallet_import_format */

	/* Convert the private key to big endian bytes */
	priv_bytes := priv.D.Bytes()

	/* Convert bytes to base-58 check encoded string with version 0x80 */
	wif = b58checkencode(0x80, priv_bytes)

	return wif
}

// CheckWIF checks that string wif is a valid Wallet Import File string.
func CheckWIF(wif string) (valid bool, err error) {
	/* Base58 Check Decode the WIF string */
	ver, pri_bytes, err := b58checkdecode(wif)
	if err != nil {
		return false, err
	}

	/* Check that the version byte is 0x80 */
	if ver != 0x80 {
		return false, fmt.Errorf("Invalid version 0x%02x for WIF, expected 0x80.", ver)
	}

	/* Check that private key byte length is 32 */
	if len(pri_bytes) != 32 {
		return false, fmt.Errorf("Invalid private key bytes length %d, expected 32.", len(pri_bytes))
	}

	return true, nil
}

// ToAddress converts a Bitcoin public key to a Bitcoin address string.
func (pub *PublicKey) ToAddress(version uint8) (address string) {
	/* See https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses */

	/* Create a new SHA256 context */
	sha256_h := sha256.New()
	/* Create a new RIPEMD160 Context */
	ripemd160_h := ripemd160.New()

	/* Convert the public key to a byte sequence */
	pub_bytes := append(pub.X.Bytes(), pub.Y.Bytes()...)

	/* Prepend 0x04 */
	pub_bytes = append([]byte{0x04}, pub_bytes...)

	/* SHA256 Hash */
	sha256_h.Reset()
	sha256_h.Write(pub_bytes)
	pub_hash_1 := sha256_h.Sum(nil)

	/* RIPEMD-160 Hash */
	ripemd160_h.Reset()
	ripemd160_h.Write(pub_hash_1)
	pub_hash_2 := ripemd160_h.Sum(nil)

	/* Convert hash bytes to base58 check encoded sequence */
	address = b58checkencode(version, pub_hash_2)

	return address
}
