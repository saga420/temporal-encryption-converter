package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/curve25519"
	"io"
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
