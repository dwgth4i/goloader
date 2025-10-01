package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncryptFile reads plainPath, encrypts with AES-256-GCM, writes encrypted blob to outPath
// and writes the hex key to keyPath. It returns the hex-encoded key on success.
func EncryptSC(rawShellCode []byte, key []byte) ([]byte, error) {

	var encryptedShellcode []byte

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("[-] Error generating AES block cipher: ", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("[-] Error setting GCM mode: ", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("error generating the nonce ", err)
	}

	encryptedShellcode = gcm.Seal(nonce, nonce, []byte(rawShellCode), nil)

	return encryptedShellcode, nil

}
