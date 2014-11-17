/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gimme-bitcoin-address
 * MIT Licensed
 */

package btcaddr

import (
	"bytes"
	"math/big"
	"testing"
)

func TestECDSA(t *testing.T) {
	/* secp256k1 elliptic curve parameters */
	var curve = &EllipticCurve{}
	curve.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	curve.A, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	curve.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	curve.G.X, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	curve.G.Y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	curve.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	curve.H, _ = new(big.Int).SetString("01", 16)

	/* Sample Private Key */
	D := []byte{0x18, 0xE1, 0x4A, 0x7B, 0x6A, 0x30, 0x7F, 0x42, 0x6A, 0x94, 0xF8, 0x11, 0x47, 0x01, 0xE7, 0xC8, 0xE7, 0x74, 0xE7, 0xF9, 0xA4, 0x7E, 0x2C, 0x20, 0x35, 0xDB, 0x29, 0xA2, 0x06, 0x32, 0x17, 0x25}
	/* Sample Corresponding Public Key */
	X := []byte{0x50, 0x86, 0x3A, 0xD6, 0x4A, 0x87, 0xAE, 0x8A, 0x2F, 0xE8, 0x3C, 0x1A, 0xF1, 0xA8, 0x40, 0x3C, 0xB5, 0x3F, 0x53, 0xE4, 0x86, 0xD8, 0x51, 0x1D, 0xAD, 0x8A, 0x04, 0x88, 0x7E, 0x5B, 0x23, 0x52}
	Y := []byte{0x2C, 0xD4, 0x70, 0x24, 0x34, 0x53, 0xA2, 0x99, 0xFA, 0x9E, 0x77, 0x23, 0x77, 0x16, 0x10, 0x3A, 0xBC, 0x11, 0xA1, 0xDF, 0x38, 0x85, 0x5E, 0xD6, 0xF2, 0xEE, 0x18, 0x7E, 0x9C, 0x58, 0x2B, 0xA6}

	/* Compute public key from private key using our elliptic curve arithmetic */
	Q := curve.pointScalarMultiply(new(big.Int).SetBytes(D), curve.G)

	/* Ensure they're equal with test vectors */
	if !bytes.Equal(Q.X.Bytes(), X) || !bytes.Equal(Q.Y.Bytes(), Y) {
		t.Error("failure computing public key from private key")
	} else {
		t.Log("success computing public key from private key")
	}

	/* Ensure our elliptic curve arithmetic believes Q is on the curve */
	if !curve.isOnCurve(Q) {
		t.Error("failure public key on curve")
	} else {
		t.Log("success public key on curve")
	}
}
