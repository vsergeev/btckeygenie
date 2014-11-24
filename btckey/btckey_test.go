/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gobtcaddr
 * MIT Licensed
 */

package btckey

import (
	"bytes"
	"math/big"
	"testing"
)

type b58Test struct {
	bytes   []byte
	encoded string
}

func TestBase58(t *testing.T) {
	var b58Vectors = []b58Test{
		{[]byte{0x4e, 0x19}, "6wi"},
		{[]byte{0x3a, 0xb7}, "5UA"},
		{[]byte{0xae, 0x0d, 0xdc, 0x9b}, "5T3W5p"},
		{[]byte{0x65, 0xe0, 0xb4, 0xc9}, "3c3E6L"},
		{[]byte{0x25, 0x79, 0x36, 0x86, 0xe9, 0xf2, 0x5b, 0x6b}, "7GYJp3ZThFG"},
		{[]byte{0x94, 0xb9, 0xac, 0x08, 0x4a, 0x0d, 0x65, 0xf5}, "RspedB5CMo2"},
	}

	/* Test base-58 encoding */
	for i := 0; i < len(b58Vectors); i++ {
		got := b58encode(b58Vectors[i].bytes)
		if got != b58Vectors[i].encoded {
			t.Fatalf("b58encode(%v): got %s, expected %s", b58Vectors[i].bytes, got, b58Vectors[i].encoded)
		}
	}
	t.Log("success b58encode() on valid vectors")

	/* Test base-58 decoding */
	for i := 0; i < len(b58Vectors); i++ {
		got, err := b58decode(b58Vectors[i].encoded)
		if err != nil {
			t.Fatalf("b58decode(%s): got error %v, expected %v", b58Vectors[i].encoded, err, b58Vectors[i].bytes)
		}
		if bytes.Compare(got, b58Vectors[i].bytes) != 0 {
			t.Fatalf("b58decode(%s): got %v, expected %v", b58Vectors[i].encoded, got, b58Vectors[i].bytes)
		}
	}
	t.Log("success b58decode() on valid vectors")

	/* Test base-58 decoding of invalid strings */
	b58InvalidVectors := []string{"5T3IW5p", "6Owi"}
	for i := 0; i < len(b58InvalidVectors); i++ {
		got, err := b58decode(b58InvalidVectors[i])
		if err == nil {
			t.Fatalf("b58decode(%s): got %v, expected error", b58InvalidVectors[i], got)
		}
		t.Logf("b58decode(%s): got expected err %v", b58InvalidVectors[i], err)
	}
	t.Log("success b58decode() on invalid vectors")
}

type b58CheckTest struct {
	ver     uint8
	bytes   []byte
	encoded string
}

func TestBase58Check(t *testing.T) {
	var b58CheckVectors = []b58CheckTest{
		{0x00, []byte{0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55, 0x67, 0x43, 0x9E, 0x5E, 0x39, 0xF8, 0x6A, 0x0D, 0x27, 0x3B, 0xEE}, "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"},
		{0x80, []byte{0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C, 0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1, 0x9D, 0x72, 0xAA, 0x1D}, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"},
	}

	/* Test base-58 check encoding */
	for i := 0; i < len(b58CheckVectors); i++ {
		got := b58checkencode(b58CheckVectors[i].ver, b58CheckVectors[i].bytes)
		if got != b58CheckVectors[i].encoded {
			t.Fatalf("b58checkencode(0x%02x, %v): got %s, expected %s", b58CheckVectors[i].ver, b58CheckVectors[i].bytes, got, b58CheckVectors[i].encoded)
		}
	}
	t.Log("success b58checkencode() on valid vectors")

	/* Test base-58 check decoding */
	for i := 0; i < len(b58CheckVectors); i++ {
		ver, got, err := b58checkdecode(b58CheckVectors[i].encoded)
		if err != nil {
			t.Fatalf("b58checkdecode(%s): got error %v, expected ver %v, bytes %v", b58CheckVectors[i].encoded, err, b58CheckVectors[i].ver, b58CheckVectors[i].bytes)
		}
		if ver != b58CheckVectors[i].ver || bytes.Compare(got, b58CheckVectors[i].bytes) != 0 {
			t.Fatalf("b58checkdecode(%s): got ver %v, bytes %v, expected ver %v, bytes %v", b58CheckVectors[i].encoded, ver, got, b58CheckVectors[i].ver, b58CheckVectors[i].bytes)
		}
	}
	t.Log("success b58checkdecode() on valid vectors")

	/* Test base-58 check decoding of invalid strings */
	b58CheckInvalidVectors := []string{
		"5T3IW5p", // Invalid base58
		"6wi",     // Missing checksum
		"6UwLL9Risc3QfPqBUvKofHmBQ7wMtjzm", // Invalid checksum
	}
	for i := 0; i < len(b58CheckInvalidVectors); i++ {
		ver, got, err := b58checkdecode(b58CheckInvalidVectors[i])
		if err == nil {
			t.Fatalf("b58checkdecode(%s): got ver %v, bytes %v, expected error", b58CheckInvalidVectors[i], ver, got)
		}
		t.Logf("b58checkdecode(%s): got expected err %v", b58CheckInvalidVectors[i], err)
	}
	t.Log("success b58checkdecode() on invalid vectors")
}

func TestCheckWIF(t *testing.T) {
	var wifVectors = []string{
		"5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V",
		"5JbDYniwPgAn3YqPUkVvrCQdJsjjFx2rV2EYeg5CAH3wNncziMm",
		"5KPaskZdrcPmrH3AFdpMF7FFBcYigwdrEfpBN9K5Ch4Ch6Bort4",
	}

	/* Check valid vectors */
	for i := 0; i < len(wifVectors); i++ {
		got, err := CheckWIF(wifVectors[i])
		if got == false {
			t.Fatalf("CheckWIF(%s): got false, error %v, expected true", wifVectors[i], err)
		}
	}
	t.Log("success CheckWIF() on valid vectors")

	var wifInvalidVectors = []string{
		"5T3IW5p", // Invalid base58
		"6wi",     // Missing checksum
		"6Mcb23muAxyXaSMhmB6B1mqkvLdWhtuFZmnZsxDczHRraMcNG",  // Invalid checksum
		"huzKTSifqNioknFPsoA7uc359rRHJQHRg42uiKn6P8Rnv5qxV5", // Invalid version byte
		"yPoVP5njSzmEVK4VJGRWWAwqnwCyLPRcMm5XyrKgYUpeXtGyM",  // Invalid private key byte length
	}

	/* Check invalid vectors */
	for i := 0; i < len(wifInvalidVectors); i++ {
		got, err := CheckWIF(wifInvalidVectors[i])
		if got == true {
			t.Fatalf("CheckWIF(%s): got true, expected false", wifInvalidVectors[i])
		}
		t.Logf("CheckWIF(%s): got false, err %v", wifInvalidVectors[i], err)
	}
	t.Log("success CheckWIF() on invalid vectors")
}

func TestExportWIF(t *testing.T) {
	/* Sample Private Key */
	D := []byte{0x18, 0xE1, 0x4A, 0x7B, 0x6A, 0x30, 0x7F, 0x42, 0x6A, 0x94, 0xF8, 0x11, 0x47, 0x01, 0xE7, 0xC8, 0xE7, 0x74, 0xE7, 0xF9, 0xA4, 0x7E, 0x2C, 0x20, 0x35, 0xDB, 0x29, 0xA2, 0x06, 0x32, 0x17, 0x25}

	var priv PrivateKey

	priv.D = new(big.Int).SetBytes(D)

	if wif := priv.ToWIF(); wif != "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V" {
		t.Fatal("failure convert private key to wif string failed")
	}

	t.Log("success PrivateKey ToWIF()")
}

func TestExportAddress(t *testing.T) {
	/* Sample Public Key */
	X := []byte{0x50, 0x86, 0x3A, 0xD6, 0x4A, 0x87, 0xAE, 0x8A, 0x2F, 0xE8, 0x3C, 0x1A, 0xF1, 0xA8, 0x40, 0x3C, 0xB5, 0x3F, 0x53, 0xE4, 0x86, 0xD8, 0x51, 0x1D, 0xAD, 0x8A, 0x04, 0x88, 0x7E, 0x5B, 0x23, 0x52}
	Y := []byte{0x2C, 0xD4, 0x70, 0x24, 0x34, 0x53, 0xA2, 0x99, 0xFA, 0x9E, 0x77, 0x23, 0x77, 0x16, 0x10, 0x3A, 0xBC, 0x11, 0xA1, 0xDF, 0x38, 0x85, 0x5E, 0xD6, 0xF2, 0xEE, 0x18, 0x7E, 0x9C, 0x58, 0x2B, 0xA6}

	var pub PublicKey

	pub.X = new(big.Int).SetBytes(X)
	pub.Y = new(big.Int).SetBytes(Y)

	/* Ensure public key to bitcoin address export matches test vector */
	if address := pub.ToAddress(0x00); address != "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM" {
		t.Fatal("failure convert public key to bitcoin address failed")
	}
	t.Log("success PublicKey ToAddress()")
}
