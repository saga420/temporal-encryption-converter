package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/saga420/temporal-encryption-converter/utils"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

// ComputeAESSharedSecret computes the shared secret using elliptic curve Diffie-Hellman
func ComputeAESSharedSecret(specs CipherKeySpecs) (sharedSecret []byte, err error) {
	// Decode the public key from hex
	pubKeyBytes, err := hex.DecodeString(specs.SharedPublicKey)
	if err != nil {
		return nil, err
	}

	// Decode the private key from hex
	privKeyBytes, err := hex.DecodeString(specs.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Check if the keys are the correct size
	if len(pubKeyBytes) != curve25519.PointSize || len(privKeyBytes) != curve25519.ScalarSize {
		return nil, fmt.Errorf("keys are not the correct size")
	}

	// fmt.Println(specs)
	// Compute the shared secret using elliptic curve Diffie-Hellman
	sharedSecret, err = curve25519.X25519(privKeyBytes, pubKeyBytes)
	if err != nil {
		return nil, err
	}

	// Convert the iterations to int
	iterations, err := utils.SafeStringToInt(specs.Iterations)
	if err != nil {
		return nil, fmt.Errorf("failed to convert iterations to int: %w", err)
	}

	// Check if the iterations are within the range
	if iterations > 8000000 {
		iterations = 8000000
	}

	// Check if the iterations are within the range
	if iterations < 4096 {
		iterations = 4096
	}

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
		return nil, err
	}

	// Create a new AES-GCM AEAD cipher
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a new nonce
	nonce := make([]byte, aesGcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
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
		return nil, err
	}

	// Create a new AES-GCM AEAD cipher
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check if the encrypted data is too short
	if len(encryptedData) < aesGcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Decrypt the data
	nonce, encryptedData := encryptedData[:aesGcm.NonceSize()], encryptedData[aesGcm.NonceSize():]
	plaintext, err := aesGcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
