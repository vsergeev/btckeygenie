/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gimme-bitcoin-address
 * MIT Licensed
 */

package main

import (
	"fmt"
	"log"
	"os"
	"github.com/vsergeev/gobtcaddr/btcaddr"
)

func main() {
	/* Redirect fatal errors to stderr */
	log.SetOutput(os.Stderr)

	/* Generate a new ECDSA keypair */
	priv, err := btcaddr.GenerateKey()
	if err != nil {
		log.Fatalf("%s\n", err)
	}

	/* Convert the public key to a bitcoin network address */
    address := priv.ToAddress(0x00)

	/* Convert the private key to a WIF string */
    wif := priv.ToWIF()

	fmt.Println("Address:", address)
	fmt.Println("    WIF:", wif)
}
