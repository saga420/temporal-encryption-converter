package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

// ComputeAESSharedSecret computes the shared secret using elliptic curve Diffie-Hellman
func ComputeAESSharedSecret(specs CipherKeySpecs) (sharedSecret []byte, err error) {
	sharedSecret, err = ComputeX25519SharedKey(specs.SharedPublicKey, specs.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Convert the iterations to int
	iterations := ParsePBKDF2Iterations(specs.Iterations)

	// Derive a 256-bit key from the shared secret using PBKDF2
	derivedSecuredKey := pbkdf2.Key(sharedSecret, []byte(specs.Salt), iterations, 32, sha256.New)
	return derivedSecuredKey, nil
}

// AesGcmEncrypt encrypts the plainData using the AES-GCM AEAD cipher
func AesGcmEncrypt(plainData []byte, specs CipherKeySpecs) ([]byte, error) {

	// Compute the shared secret
	sharedKey, err := ComputeAESSharedSecret(specs)
	if err != nil {
		return nil, err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher block: %w", err)
	}

	// Create a new AES-GCM AEAD cipher
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES-GCM AEAD cipher: %w", err)
	}

	// Create a new nonce
	nonce := make([]byte, aesGcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to create new nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := aesGcm.Seal(nonce, nonce, plainData, nil)
	return ciphertext, nil
}

// AesGcmDecrypt decrypts the given data using AES-GCM.
func AesGcmDecrypt(encryptedData []byte, specs CipherKeySpecs) ([]byte, error) {
	// Compute the shared secret
	sharedKey, err := ComputeAESSharedSecret(specs)
	if err != nil {
		return nil, err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher block: %w", err)
	}

	// Create a new AES-GCM AEAD cipher
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES-GCM AEAD cipher: %w", err)
	}

	// Check if the encrypted data is too short
	if len(encryptedData) < aesGcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Decrypt the data
	nonce, encryptedData := encryptedData[:aesGcm.NonceSize()], encryptedData[aesGcm.NonceSize():]
	plaintext, err := aesGcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}
