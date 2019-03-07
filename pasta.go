package pasta

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/benji-vesterby/pasta/crypt"
	"github.com/gtank/cryptopasta"
)

func main() {
	var err error

	// Setting up config arguments for starting the job runner
	generateKey := flag.Bool("g", false, "Generate new key to use for encryption")
	decrypt := flag.Bool("d", false, "Decrypt the value passed in through the -v flag")
	key := flag.String("k", "", "The encryption key to use for encryption or decryption")
	value := flag.String("v", "", "The value to be encrypted or decrypted")

	flag.Parse()

	if *generateKey {

		// Generate a new encryption key to be used
		if ekey := cryptopasta.NewEncryptionKey(); ekey != nil {

			var outKey []byte
			if outKey, err = crypt.ConvertToByteSlice(ekey); err == nil {

				fmt.Printf("Encryption Key: [%s]\n", base64.StdEncoding.EncodeToString(outKey))
			} else {
				fmt.Printf("Error while converting key to byte slice | Error: [%s]\n", err.Error())
			}
		} else {
			fmt.Printf("Error while generating encryption key\n")
		}
	} else {
		// Default to encryption
		if *decrypt {
			// Decrypt

			var decryptedValue string
			if decryptedValue, err = crypt.Decrypt(*key, *value); err == nil {
				fmt.Printf("Decrypted Value: [%s]\n", decryptedValue)
			} else {
				fmt.Println(err.Error())
			}
		} else {

			var encryptedValue string
			if encryptedValue, err = crypt.Encrypt(*key, *value); err == nil {
				fmt.Printf("Encrypted Value: [%s]\n", encryptedValue)
			} else {
				fmt.Println(err.Error())
			}
		}
	}
}
