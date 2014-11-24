/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gobtcaddr
 * MIT Licensed
 */

package main

import (
	"encoding/base64"
	"fmt"
	"github.com/vsergeev/gobtcaddr/btckey"
	"log"
	"os"
)

func byteString(b []byte) (s string) {
	s = ""
	for i := 0; i < len(b); i++ {
		s += fmt.Sprintf("%02X", b[i])
	}
	return s
}

func main() {
	/* Redirect fatal errors to stderr */
	log.SetOutput(os.Stderr)

	var priv btckey.PrivateKey
	var err error

	/* Import WIF from first argument */
	if len(os.Args) > 1 {
		err = priv.FromWIF(os.Args[1])
		if err != nil {
			log.Fatalf("Importing WIF: %s\n", err)
		}
	} else {
		/* Generate a new Bitcoin keypair */
		priv, err = btckey.GenerateKey()
		if err != nil {
			log.Fatalf("Generating keypair: %s\n", err)
		}
	}

	/* Convert to Address */
	address := priv.ToAddress(0x00)
	/* Convert to Public Key Bytes (65 bytes) */
	pub_bytes := priv.PublicKey.ToBytes()
	pub_bytes_str := byteString(pub_bytes)
	pub_bytes_b64 := base64.StdEncoding.EncodeToString(pub_bytes)

	/* Convert to WIF */
	wif := priv.ToWIF()
	/* Convert to Private Key Bytes (32 bytes) */
	pri_bytes := priv.ToBytes()
	pri_bytes_str := byteString(pri_bytes)
	pri_bytes_b64 := base64.StdEncoding.EncodeToString(pri_bytes)

	fmt.Printf("     Bitcoin Address: %s\n", address)
	fmt.Printf("    Public Key Bytes: %s\n", pub_bytes_str[0:65])
	fmt.Printf("                      %s\n", pub_bytes_str[65:])
	fmt.Printf("   Public Key Base64: %s\n", pub_bytes_b64)
	fmt.Println()
	fmt.Printf("     Private Key WIF: %s\n", wif)
	fmt.Printf("   Private Key Bytes: %s\n", pri_bytes_str)
	fmt.Printf("  Private Key Base64: %s\n", pri_bytes_b64)
}
