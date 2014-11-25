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
	b58InvalidVectors := []string{
		"5T3IW5p", // Invalid character I
		"6Owi",    // Invalid character O
	}

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
		{0x00, []byte{0x00, 0x00, 0x00, 0x00, 0x60, 0x06, 0x95, 0x3D, 0x55, 0x67, 0x43, 0x9E, 0x5E, 0x39, 0xF8, 0x6A, 0x0D, 0x27, 0x3B, 0xEE}, "111112LbMksD9tCRVsyW67atmDssDkHHG"},
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

func TestDerive(t *testing.T) {
	/* Sample Private Key */
	D := []byte{0x18, 0xE1, 0x4A, 0x7B, 0x6A, 0x30, 0x7F, 0x42, 0x6A, 0x94, 0xF8, 0x11, 0x47, 0x01, 0xE7, 0xC8, 0xE7, 0x74, 0xE7, 0xF9, 0xA4, 0x7E, 0x2C, 0x20, 0x35, 0xDB, 0x29, 0xA2, 0x06, 0x32, 0x17, 0x25}
	/* Sample Public Key */
	X := []byte{0x50, 0x86, 0x3A, 0xD6, 0x4A, 0x87, 0xAE, 0x8A, 0x2F, 0xE8, 0x3C, 0x1A, 0xF1, 0xA8, 0x40, 0x3C, 0xB5, 0x3F, 0x53, 0xE4, 0x86, 0xD8, 0x51, 0x1D, 0xAD, 0x8A, 0x04, 0x88, 0x7E, 0x5B, 0x23, 0x52}
	Y := []byte{0x2C, 0xD4, 0x70, 0x24, 0x34, 0x53, 0xA2, 0x99, 0xFA, 0x9E, 0x77, 0x23, 0x77, 0x16, 0x10, 0x3A, 0xBC, 0x11, 0xA1, 0xDF, 0x38, 0x85, 0x5E, 0xD6, 0xF2, 0xEE, 0x18, 0x7E, 0x9C, 0x58, 0x2B, 0xA6}

	var priv PrivateKey

	priv.D = new(big.Int).SetBytes(D)

	/* Derive public key from private key */
	_, err := priv.derive()
	if err != nil {
		t.Fatalf("priv.derive(): got error %v, expected success", err)
	}

	/* Compare */
	if bytes.Compare(priv.X.Bytes(), X) != 0 {
		t.Fatal("derived public key X bytes do not match test vector")
	}
	if bytes.Compare(priv.Y.Bytes(), Y) != 0 {
		t.Fatal("derived public key Y bytes do not match test vector")
	}

	t.Log("success derive() on private key")
}

type keyPairTest struct {
	wif        string
	priv_bytes []byte
	address    string
	pub_bytes  []byte
}

var keyPairVectors = []keyPairTest{
	{
		"5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V",
		[]byte{0x18, 0xE1, 0x4A, 0x7B, 0x6A, 0x30, 0x7F, 0x42, 0x6A, 0x94, 0xF8, 0x11, 0x47, 0x01, 0xE7, 0xC8, 0xE7, 0x74, 0xE7, 0xF9, 0xA4, 0x7E, 0x2C, 0x20, 0x35, 0xDB, 0x29, 0xA2, 0x06, 0x32, 0x17, 0x25},
		"16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
		[]byte{0x04, 0x50, 0x86, 0x3A, 0xD6, 0x4A, 0x87, 0xAE, 0x8A, 0x2F, 0xE8, 0x3C, 0x1A, 0xF1, 0xA8, 0x40, 0x3C, 0xB5, 0x3F, 0x53, 0xE4, 0x86, 0xD8, 0x51, 0x1D, 0xAD, 0x8A, 0x04, 0x88, 0x7E, 0x5B, 0x23, 0x52, 0x2C, 0xD4, 0x70, 0x24, 0x34, 0x53, 0xA2, 0x99, 0xFA, 0x9E, 0x77, 0x23, 0x77, 0x16, 0x10, 0x3A, 0xBC, 0x11, 0xA1, 0xDF, 0x38, 0x85, 0x5E, 0xD6, 0xF2, 0xEE, 0x18, 0x7E, 0x9C, 0x58, 0x2B, 0xA6},
	},
	{
		"5JbDYniwPgAn3YqPUkVvrCQdJsjjFx2rV2EYeg5CAH3wNncziMm",
		[]byte{0x66, 0x05, 0x27, 0x76, 0x50, 0x29, 0xF5, 0xF1, 0xBC, 0x6D, 0xFD, 0x58, 0x21, 0xA7, 0xFF, 0x33, 0x6C, 0x10, 0xED, 0xA3, 0x91, 0xE1, 0x9B, 0xB4, 0x51, 0x7D, 0xB4, 0xE2, 0x3E, 0x5B, 0x11, 0x2F},
		"17FBpEDgirwQJTvHT6ZgSirWSCbdTB9f76",
		[]byte{0x04, 0xA8, 0x3B, 0x8D, 0xE8, 0x93, 0x46, 0x7D, 0x3A, 0x88, 0xD9, 0x59, 0xC0, 0xEB, 0x40, 0x32, 0xD9, 0xCE, 0x3B, 0xF8, 0x0F, 0x17, 0x5D, 0x4D, 0x9E, 0x75, 0x89, 0x2A, 0x3E, 0xBB, 0x8A, 0xB7, 0xE5, 0x37, 0x0F, 0x72, 0x33, 0x28, 0xC2, 0x4B, 0x7A, 0x97, 0xFE, 0x34, 0x06, 0x3B, 0xA6, 0x8F, 0x25, 0x3F, 0xB0, 0x8F, 0x86, 0x45, 0xD7, 0xC8, 0xB9, 0xA4, 0xFF, 0x98, 0xE3, 0xC2, 0x9E, 0x7F, 0x0D},
	},
	{
		"5KPaskZdrcPmrH3AFdpMF7FFBcYigwdrEfpBN9K5Ch4Ch6Bort4",
		[]byte{0xCF, 0x4D, 0xBE, 0x1A, 0xBC, 0xB0, 0x61, 0xDB, 0x64, 0xCC, 0x87, 0x40, 0x4A, 0xB7, 0x36, 0xB6, 0xA5, 0x6E, 0x8C, 0xDD, 0x40, 0xE9, 0x84, 0x61, 0x44, 0x58, 0x22, 0x40, 0xC5, 0x36, 0x67, 0x58},
		"1K1EJ6Zob7mr6Wye9mF1pVaU4tpDhrYMKJ",
		[]byte{0x04, 0xF6, 0x80, 0x55, 0x66, 0x78, 0xE2, 0x50, 0x84, 0xA8, 0x2F, 0xA3, 0x9E, 0x1B, 0x1D, 0xFD, 0x09, 0x44, 0xF7, 0xE6, 0x9F, 0xDD, 0xAA, 0x4E, 0x03, 0xCE, 0x93, 0x4B, 0xD6, 0xB2, 0x91, 0xDC, 0xA0, 0x52, 0xC1, 0x0B, 0x72, 0x1D, 0x34, 0x44, 0x7E, 0x17, 0x37, 0x21, 0xFB, 0x01, 0x51, 0xC6, 0x8D, 0xE1, 0x10, 0x6B, 0xAD, 0xB0, 0x89, 0xFB, 0x66, 0x15, 0x23, 0xB8, 0x30, 0x2A, 0x90, 0x97, 0xF5},
	},
	{
		"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsrgA9tXshp",
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00},
		"17imJe7o4mpq2MMfZ328evDJQfbt6ShvxA",
		[]byte{0x04, 0x24, 0x1F, 0xEB, 0xB8, 0xE2, 0x3C, 0xBD, 0x77, 0xD6, 0x64, 0xA1, 0x8F, 0x66, 0xAD, 0x62, 0x40, 0xAA, 0xEC, 0x6E, 0xCD, 0xC8, 0x13, 0xB0, 0x88, 0xD5, 0xB9, 0x01, 0xB2, 0xE2, 0x85, 0x13, 0x1F, 0x51, 0x33, 0x78, 0xD9, 0xFF, 0x94, 0xF8, 0xD3, 0xD6, 0xC4, 0x20, 0xBD, 0x13, 0x98, 0x1D, 0xF8, 0xCD, 0x50, 0xFD, 0x0F, 0xBD, 0x0C, 0xB5, 0xAF, 0xAB, 0xB3, 0xE6, 0x6F, 0x27, 0x50, 0x02, 0x6D},
	},
}

var wifInvalidVectors = []string{
	"5T3IW5p", // Invalid base58
	"6wi",     // Missing checksum
	"6Mcb23muAxyXaSMhmB6B1mqkvLdWhtuFZmnZsxDczHRraMcNG",  // Invalid checksum
	"huzKTSifqNioknFPsoA7uc359rRHJQHRg42uiKn6P8Rnv5qxV5", // Invalid version byte
	"yPoVP5njSzmEVK4VJGRWWAwqnwCyLPRcMm5XyrKgYUpeXtGyM",  // Invalid private key byte length
}

func TestPrivateKeyBytes(t *testing.T) {
	var priv PrivateKey

	for i := 0; i < len(keyPairVectors); i++ {
		err := priv.FromBytes(keyPairVectors[i].priv_bytes)
		if err != nil {
			t.Fatalf("priv.FromBytes(D): got error %v, expected success on index %d", err, i)
		}
		if bytes.Compare(keyPairVectors[i].priv_bytes, priv.ToBytes()) != 0 {
			t.Fatalf("private key bytes do not match test vector on index %d", i)
		}
		if bytes.Compare(keyPairVectors[i].pub_bytes, priv.PublicKey.ToBytes()) != 0 {
			t.Fatalf("public key bytes do not match test vecotr index %d", i)
		}
	}

	/* Invalid private key */
	err := priv.FromBytes(keyPairVectors[0].priv_bytes[0:31])
	if err == nil {
		t.Fatalf("priv.FromBytes(D): got success, expected error")
	}

	t.Log("success PrivateKey FromBytes() and ToBytes()")
}

func TestPublicKeyBytes(t *testing.T) {
	var pub PublicKey

	for i := 0; i < len(keyPairVectors); i++ {
		err := pub.FromBytes(keyPairVectors[i].pub_bytes)
		if err != nil {
			t.Fatalf("pub.FromBytes(XY): got error %v, expected success on index %d", err, i)
		}
		if bytes.Compare(keyPairVectors[i].pub_bytes, pub.ToBytes()) != 0 {
			t.Fatalf("public key bytes do not match test vectors on index %d", i)
		}
	}

	/* Test invalid public key */
	err := pub.FromBytes(keyPairVectors[0].pub_bytes[0:45])
	if err == nil {
		t.Fatal("pub.FromBytes(XY): got success, expected error")
	}

	t.Log("success PublicKey FromBytes() and ToBytes()")
}

func TestCheckWIF(t *testing.T) {
	/* Check valid vectors */
	for i := 0; i < len(keyPairVectors); i++ {
		got, err := CheckWIF(keyPairVectors[i].wif)
		if got == false {
			t.Fatalf("CheckWIF(%s): got false, error %v, expected true", keyPairVectors[i].wif, err)
		}
	}
	t.Log("success CheckWIF() on valid vectors")

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

func TestImportWIF(t *testing.T) {
	var priv PrivateKey

	/* Check valid vectors */
	for i := 0; i < len(keyPairVectors); i++ {
		err := priv.FromWIF(keyPairVectors[i].wif)
		if err != nil {
			t.Fatalf("priv.FromWIF(%s): got error %v, expected success", keyPairVectors[i].wif, err)
		}
		if bytes.Compare(keyPairVectors[i].priv_bytes, priv.ToBytes()) != 0 {
			t.Fatalf("private key bytes do not match test vector index %d", i)
		}
		if bytes.Compare(keyPairVectors[i].pub_bytes, priv.PublicKey.ToBytes()) != 0 {
			t.Fatalf("public key bytes do not match test vecotr index %d", i)
		}
	}
	t.Log("success priv.FromWIF() on valid vectors")

	/* Check invalid vectors */
	for i := 0; i < len(wifInvalidVectors); i++ {
		err := priv.FromWIF(wifInvalidVectors[i])
		if err == nil {
			t.Fatalf("priv.FromWIF(%s): got success, expected error", wifInvalidVectors[i])
		}
		t.Logf("priv.FromWIF(%s): got err %v", wifInvalidVectors[i], err)
	}
	t.Log("success priv.FromWIF() on invalid vectors")
}

func TestExportWIF(t *testing.T) {
	var priv PrivateKey

	/* Check valid vectors */
	for i := 0; i < len(keyPairVectors); i++ {
		err := priv.FromBytes(keyPairVectors[i].priv_bytes)
		if err != nil {
			t.Fatalf("priv.FromBytes(): got error %v, expected success on index %d", err, i)
		}
		wif := priv.ToWIF()
		if wif != keyPairVectors[i].wif {
			t.Fatalf("priv.ToWIF() %s != expected %s", wif, keyPairVectors[i].wif)
		}
	}
	t.Log("success PrivateKey ToWIF()")
}

func TestExportAddress(t *testing.T) {
	var pub PublicKey

	/* Check valid vectors */
	for i := 0; i < len(keyPairVectors); i++ {
		err := pub.FromBytes(keyPairVectors[i].pub_bytes)
		if err != nil {
			t.Fatalf("pub.FromBytes(): got error %v, expected success on index %d", err, i)
		}
		address := pub.ToAddress(0x00)
		if address != keyPairVectors[i].address {
			t.Fatalf("pub.ToAddress() %s != expected %s", address, keyPairVectors[i].address)
		}
	}
	t.Log("success PublicKey ToAddress()")
}
