package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"io"
	"strconv"
)

type AlgoMethod string

const (
	XChaCha20_Poly1305_PBKDF2_Curve25519 AlgoMethod = "XChaCha20_Poly1305_PBKDF2_Curve25519"
	AES256_GCM_PBKDF2_Curve25519         AlgoMethod = "AES256_GCM_PBKDF2_Curve25519"
)

type CipherKeySpecs struct {
	Salt            string     `json:"salt"`
	Iterations      string     `json:"iterations"`
	SharedPublicKey string     `json:"sharedPublicKey"`
	PrivateKey      string     `json:"privateKey"`
	Algo            AlgoMethod `json:"algo"`
}

type X25519KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// GenerateKeyPair generates a new X25519 key pair.
func GenerateKeyPair() (keyPair X25519KeyPair, err error) {
	privateKeyBytes := make([]byte, curve25519.ScalarSize)
	if _, err = io.ReadFull(rand.Reader, privateKeyBytes); err != nil {
		return X25519KeyPair{}, err
	}

	publicKeyBytes, err := curve25519.X25519(privateKeyBytes, curve25519.Basepoint)
	if err != nil {
		return X25519KeyPair{}, err
	}

	return X25519KeyPair{
		PublicKey:  hex.EncodeToString(publicKeyBytes),
		PrivateKey: hex.EncodeToString(privateKeyBytes),
	}, nil
}

// ComputeX25519SharedKey computes the shared secret using elliptic curve Diffie-Hellman
// SharedPublicKey and PrivateKey must be hex encoded as strings
// Returns the shared secret as a byte slice
func ComputeX25519SharedKey(SharedPublicKey, PrivateKey string) (sharedSecret []byte, err error) {
	// Decode the public key from hex
	pubKeyBytes, err := hex.DecodeString(SharedPublicKey)
	if err != nil {
		return nil, err
	}

	// Decode the private key from hex
	privKeyBytes, err := hex.DecodeString(PrivateKey)
	if err != nil {
		return nil, err
	}

	// Check if the keys are the correct size
	if len(pubKeyBytes) != curve25519.PointSize || len(privKeyBytes) != curve25519.ScalarSize {
		return nil, fmt.Errorf("keys are not the correct size")
	}

	// Compute the shared secret using elliptic curve Diffie-Hellman
	sharedSecret, err = curve25519.X25519(privKeyBytes, pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

// SafeStringToInt converts a string to an int
// Returns an error if the string cannot be converted to an int
func SafeStringToInt(s string) (int, error) {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("conversion error: %w", err)
	}
	return i, nil
}

// GenerateSalt generates a random salt
// Returns the salt as a hex encoded string
func GenerateSalt() (string, error) {
	salt := make([]byte, 64)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(salt), nil
}

// ParsePBKDF2Iterations parses the PBKDF2 iterations
// Returns the iterations as an int
func ParsePBKDF2Iterations(iterations string) int {
	i, err := SafeStringToInt(iterations)

	if err != nil {
		// If the iterations are not an int, return the default value
		return 4096
	}
	// Check if the iterations are within the range
	if i > 8000000 {
		i = 8000000
	}

	// Check if the iterations are within the range
	if i < 4096 {
		i = 4096
	}

	return i
}
