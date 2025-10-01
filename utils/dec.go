package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func DecryptSC(shellcode []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(shellcode) < nonceSize {
		return nil, fmt.Errorf("Shellcode too short")
	}

	nonce, encryptedShellcode := shellcode[:nonceSize], shellcode[nonceSize:]
	return gcm.Open(nil, nonce, encryptedShellcode, nil)
}
