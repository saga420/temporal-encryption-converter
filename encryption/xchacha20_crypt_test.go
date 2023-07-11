package encryption

import (
	"encoding/hex"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)
	require.Len(t, keyPair.PublicKey, curve25519.PointSize*2)   // Sizes in hex, so *2
	require.Len(t, keyPair.PrivateKey, curve25519.ScalarSize*2) // Sizes in hex, so *2
}

func TestComputeSharedSecret(t *testing.T) {
	// Generate key pair 1
	keyPair1, err := GenerateKeyPair()
	require.NoError(t, err)

	// Generate key pair 2
	keyPair2, err := GenerateKeyPair()
	require.NoError(t, err)

	specs := CipherKeySpecs{
		Salt:            "somesalt",
		Iterations:      "50000",
		SharedPublicKey: keyPair2.PublicKey,
		PrivateKey:      keyPair1.PrivateKey,
	}

	secret, err := ComputeChaChaSharedSecret(specs)
	require.NoError(t, err)
	require.Len(t, secret, chacha20poly1305.KeySize)

	// Now compute the shared secret from the other side and compare
	specs.SharedPublicKey = keyPair1.PublicKey
	specs.PrivateKey = keyPair2.PrivateKey

	secret2, err := ComputeChaChaSharedSecret(specs)
	require.NoError(t, err)
	require.Len(t, secret2, chacha20poly1305.KeySize)

	// The two secrets should match
	require.Equal(t, secret, secret2)
}

func TestChaChaEncryptDecrypt(t *testing.T) {
	// Generate a key pair
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	// Use self as shared public key to simulate symmetric encryption
	specs := CipherKeySpecs{
		Salt:            "somesalt",
		Iterations:      "50000",
		SharedPublicKey: keyPair.PublicKey,
		PrivateKey:      keyPair.PrivateKey,
	}

	data := []byte("Hello, World!")
	encrypted, err := ChaChaEncrypt(data, specs)
	require.NoError(t, err)

	decrypted, err := ChaChaDecrypt(encrypted, specs)
	require.NoError(t, err)

	require.Equal(t, data, decrypted)
}

func TestChaChaDecryptError(t *testing.T) {
	specs := CipherKeySpecs{
		Salt:            "somesalt",
		Iterations:      "50000",
		SharedPublicKey: "badkey",
		PrivateKey:      "badkey",
	}

	_, err := ChaChaDecrypt([]byte("bad data"), specs)
	require.Error(t, err)

	// Use a well formatted, but random key
	randBytes := make([]byte, curve25519.PointSize)
	_, _ = hex.Decode(randBytes, []byte("b8e96f2a79f73fb6a5113f42e3f4c3575f2aee68194082e9db309a5d8b3c5062"))

	specs.SharedPublicKey = hex.EncodeToString(randBytes)
	specs.PrivateKey = hex.EncodeToString(randBytes)

	_, err = ChaChaDecrypt([]byte("bad data"), specs)
	require.Error(t, err)
}
