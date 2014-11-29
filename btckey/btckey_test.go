/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gobtcaddr
 * MIT Licensed
 */

package btckey

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func hex2bytes(hexstring string) (b []byte) {
	b, _ = hex.DecodeString(hexstring)
	return b
}

func TestBase58(t *testing.T) {
	var b58Vectors = []struct {
		bytes   []byte
		encoded string
	}{
		{hex2bytes("4e19"), "6wi"},
		{hex2bytes("3ab7"), "5UA"},
		{hex2bytes("ae0ddc9b"), "5T3W5p"},
		{hex2bytes("65e0b4c9"), "3c3E6L"},
		{hex2bytes("25793686e9f25b6b"), "7GYJp3ZThFG"},
		{hex2bytes("94b9ac084a0d65f5"), "RspedB5CMo2"},
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

func TestBase58Check(t *testing.T) {
	var b58CheckVectors = []struct {
		ver     uint8
		bytes   []byte
		encoded string
	}{
		{0x00, hex2bytes("010966776006953D5567439E5E39F86A0D273BEE"), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"},
		{0x00, hex2bytes("000000006006953D5567439E5E39F86A0D273BEE"), "111112LbMksD9tCRVsyW67atmDssDkHHG"},
		{0x80, hex2bytes("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"), "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"},
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
	D := hex2bytes("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")
	/* Sample Public Key */
	X := hex2bytes("50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352")
	Y := hex2bytes("2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6")

	var priv PrivateKey

	priv.D = new(big.Int).SetBytes(D)

	/* Derive public key from private key */
	priv.derive()

	/* Compare */
	if bytes.Compare(priv.X.Bytes(), X) != 0 {
		t.Fatal("derived public key X bytes do not match test vector")
	}
	if bytes.Compare(priv.Y.Bytes(), Y) != 0 {
		t.Fatal("derived public key Y bytes do not match test vector")
	}

	t.Log("success derive() on private key")
}

var keyPairVectors = []struct {
	wif        string
	priv_bytes []byte
	address    string
	pub_bytes  []byte
}{
	{
		"5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V",
		hex2bytes("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"),
		"16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
		hex2bytes("0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6"),
	},
	{
		"5JbDYniwPgAn3YqPUkVvrCQdJsjjFx2rV2EYeg5CAH3wNncziMm",
		hex2bytes("660527765029F5F1BC6DFD5821A7FF336C10EDA391E19BB4517DB4E23E5B112F"),
		"17FBpEDgirwQJTvHT6ZgSirWSCbdTB9f76",
		hex2bytes("04A83B8DE893467D3A88D959C0EB4032D9CE3BF80F175D4D9E75892A3EBB8AB7E5370F723328C24B7A97FE34063BA68F253FB08F8645D7C8B9A4FF98E3C29E7F0D"),
	},
	{
		"5KPaskZdrcPmrH3AFdpMF7FFBcYigwdrEfpBN9K5Ch4Ch6Bort4",
		hex2bytes("CF4DBE1ABCB061DB64CC87404AB736B6A56E8CDD40E9846144582240C5366758"),
		"1K1EJ6Zob7mr6Wye9mF1pVaU4tpDhrYMKJ",
		hex2bytes("04F680556678E25084A82FA39E1B1DFD0944F7E69FDDAA4E03CE934BD6B291DCA052C10B721D34447E173721FB0151C68DE1106BADB089FB661523B8302A9097F5"),
	},
	{
		"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsrgA9tXshp",
		hex2bytes("0000000000000000000000000000000000000000000000000000000000000400"),
		"17imJe7o4mpq2MMfZ328evDJQfbt6ShvxA",
		hex2bytes("04241FEBB8E23CBD77D664A18F66AD6240AAEC6ECDC813B088D5B901B2E285131F513378D9FF94F8D3D6C420BD13981DF8CD50FD0FBD0CB5AFABB3E66F2750026D"),
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
