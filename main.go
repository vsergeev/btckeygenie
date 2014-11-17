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
	/* Usage */
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <private key directory path> [label]\n\n", os.Args[0])
		fmt.Printf("Private Key Filename Format\n\n\tYYYY-MM-DD_<Unix Timestamp>_<PID>_<optional label>.txt\n\n")
		fmt.Printf("Version 1.0 - https://github.com/vsergeev/gobtcaddr\n")
		os.Exit(1)
	}

	/* Redirect fatal errors to stderr */
	log.SetOutput(os.Stderr)

	/* Extract directory argument */
	dir := os.Args[1]
	/* Extract label argument */
	label := ""
	if len(os.Args) > 2 {
		label = os.Args[2]
	}

	/* Generate a new ECDSA keypair */
	prikey, pubkey, err := btcaddr.GenerateKeyPair()
	if err != nil {
		log.Fatalf("%s\n", err)
	}

	/* Write the private key to a file */
	err = btcaddr.Write_Prikey(prikey, dir, label)
	if err != nil {
		log.Fatalf("%s\n", err)
	}

	/* Convert the public key to a bitcoin network address */
	address := btcaddr.PubkeyToAddress(pubkey, 0x00)

	/* Print bitcoin address */
	fmt.Println(address)
}
