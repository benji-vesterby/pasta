package crypt

import (
	"encoding/base64"
	"fmt"
	"github.com/gtank/cryptopasta"
	"github.com/pkg/errors"
)

// Encrypt encrypts the value using the key passed into the method
func Encrypt(key string, value string) (cyphertext string, err error) {
	if len(value) > 0 {
		var keyValue []byte
		if keyValue, err = base64.StdEncoding.DecodeString(key); err == nil {

			ekey := [32]byte{}
			copy(ekey[:], keyValue)
			// Encrypt
			var encryptedValue []byte
			if encryptedValue, err = cryptopasta.Encrypt([]byte(value), &ekey); err == nil {

				// Set cyphertext to newly encrypted value
				cyphertext = base64.StdEncoding.EncodeToString(encryptedValue)
			} else {
				err = fmt.Errorf("error while encrypting value | Error: [%s]", err.Error())
			}
		} else {
			err = fmt.Errorf("error while encrypting value | Error: [%s]", err.Error())
		}
	} else {
		err = errors.New("empty value passed to Encrypt")
	}

	return cyphertext, err
}

// Decrypt decrypts the cyphertext using the key that was passed
func Decrypt(key string, cyphertext string) (value string, err error) {

	if len(cyphertext) > 0 {
		var keyValue []byte
		if keyValue, err = base64.StdEncoding.DecodeString(key); err == nil {

			ekey := [32]byte{}
			copy(ekey[:], keyValue)

			var decodedValue []byte
			if decodedValue, err = base64.StdEncoding.DecodeString(cyphertext); err == nil {

				var decryptedValue []byte
				if decryptedValue, err = cryptopasta.Decrypt(decodedValue, &ekey); err == nil {

					// Return the decrypted value
					value = string(decryptedValue)
				} else {
					err = fmt.Errorf("error while decrypting value | Error: [%s]", err.Error())
				}
			} else {
				err = fmt.Errorf("error while decoding base64 value | Error: [%s]", err.Error())
			}
		} else {
			err = fmt.Errorf("error while encrypting value | Error: [%s]", err.Error())
		}
	} else {
		err = errors.New("empty cyphertext passed to Decrypt")
	}

	return value, err
}

// ConvertToByteSlice converts the *32byte array to a go byte slice
func ConvertToByteSlice(bytesIn *[32]byte) (bytesOut []byte, err error) {

	if bytesIn != nil {
		bytesOut = make([]byte, len(bytesIn))

		// Since the lengths are exactly the same we can directly set indexes in the bytes out slice
		for index, bvalue := range bytesIn {

			bytesOut[index] = bvalue
		}
	} else {
		err = fmt.Errorf("invalid bytes passed to converter empty array")
	}

	return bytesOut, err
}
