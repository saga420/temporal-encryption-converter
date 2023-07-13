package encryption

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// ComputeChaChaSharedSecret computes the shared secret using elliptic curve Diffie-Hellman
func ComputeChaChaSharedSecret(specs CipherKeySpecs) (sharedSecret []byte, err error) {
	sharedSecret, err = ComputeX25519SharedKey(specs.SharedPublicKey, specs.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Convert the iterations to int
	iterations := ParsePBKDF2Iterations(specs.Iterations)

	// Derive a 256-bit key from the shared secret using PBKDF2
	sharedSecret = pbkdf2.Key(sharedSecret, []byte(specs.Salt), iterations, chacha20poly1305.KeySize, sha256.New)
	return sharedSecret, nil
}

// ChaChaEncrypt encrypts the plainData using the ChaCha20-Poly1305 AEAD cipher
func ChaChaEncrypt(plainData []byte, specs CipherKeySpecs) ([]byte, error) {
	// Compute the shared secret
	sharedKey, err := ComputeChaChaSharedSecret(specs)
	if err != nil {
		return nil, err
	}

	// Create a new ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the plainData
	return aead.Seal(nonce, nonce, plainData, nil), nil
}

// ChaChaDecrypt decrypts the encryptedData using the ChaCha20-Poly1305 AEAD cipher
func ChaChaDecrypt(encryptedData []byte, specs CipherKeySpecs) ([]byte, error) {
	// Compute the shared secret
	sharedKey, err := ComputeChaChaSharedSecret(specs)
	if err != nil {
		return nil, err
	}

	// Create a new ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, err
	}

	// Check if the encryptedData is too short
	if len(encryptedData) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("ciphertext too short: %v", encryptedData)
	}

	// Decrypt the encryptedData
	nonce, encryptedData := encryptedData[:chacha20poly1305.NonceSizeX], encryptedData[chacha20poly1305.NonceSizeX:]
	return aead.Open(nil, nonce, encryptedData, nil)
}
