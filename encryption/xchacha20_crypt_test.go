package encryption_test

import (
	"github.com/saga420/temporal-encryption-converter/encryption"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestComputeChaChaSharedSecret verifies that the shared secret is computed correctly.
func TestComputeChaChaSharedSecret(t *testing.T) {
	keyPiar1, err := encryption.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPiar1)
	require.IsTypef(t, encryption.X25519KeyPair{}, keyPiar1, "keyPiar1 is not of type encryption.KeyPair")
	keyPiar2, err := encryption.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPiar2)
	require.IsTypef(t, encryption.X25519KeyPair{}, keyPiar2, "keyPiar2 is not of type encryption.KeyPair")
	specs := encryption.CipherKeySpecs{
		Salt:            "some_salt",
		Iterations:      "5000",
		SharedPublicKey: keyPiar2.PublicKey,
		PrivateKey:      keyPiar1.PrivateKey,
		Algo:            encryption.XChaCha20_Poly1305_PBKDF2_Curve25519,
	}

	sharedSecret, err := encryption.ComputeChaChaSharedSecret(specs)
	require.NoError(t, err)
	require.NotNil(t, sharedSecret)
}

// TestChaChaEncrypt verifies that data is correctly encrypted with the ChaCha20-Poly1305 AEAD cipher.
func TestChaChaEncrypt(t *testing.T) {
	keyPiar1, err := encryption.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPiar1)
	require.IsTypef(t, encryption.X25519KeyPair{}, keyPiar1, "keyPiar1 is not of type encryption.KeyPair")
	keyPiar2, err := encryption.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPiar2)
	require.IsTypef(t, encryption.X25519KeyPair{}, keyPiar2, "keyPiar2 is not of type encryption.KeyPair")

	specs := encryption.CipherKeySpecs{
		Salt:            "some_salt",
		Iterations:      "5000",
		SharedPublicKey: keyPiar2.PublicKey,
		PrivateKey:      keyPiar1.PublicKey,
		Algo:            encryption.XChaCha20_Poly1305_PBKDF2_Curve25519,
	}

	plainData := []byte("This is a test.")
	encryptedData, err := encryption.ChaChaEncrypt(plainData, specs)
	require.NoError(t, err)
	require.NotNil(t, encryptedData)

	// The encrypted data should not be equal to the plain data
	require.NotEqual(t, encryptedData, plainData)
}

func TestChaChaEncryptError(t *testing.T) {
	specs := encryption.CipherKeySpecs{
		Salt:            "some_salt",
		Iterations:      "5000",
		SharedPublicKey: "xxx",
		PrivateKey:      "222",
		Algo:            encryption.XChaCha20_Poly1305_PBKDF2_Curve25519,
	}

	plainData := []byte("This is a test.")
	encryptedData, err := encryption.ChaChaEncrypt(plainData, specs)
	require.Error(t, err)
	require.Nil(t, encryptedData)

	// The encrypted data should not be equal to the plain data
	require.NotEqual(t, encryptedData, plainData)
}

// TestChaChaDecrypt verifies that data is correctly decrypted with the ChaCha20-Poly1305 AEAD cipher.
func TestChaChaDecrypt(t *testing.T) {
	keyPiar1, err := encryption.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPiar1)
	require.IsTypef(t, encryption.X25519KeyPair{}, keyPiar1, "keyPiar1 is not of type encryption.KeyPair")
	keyPiar2, err := encryption.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPiar2)
	require.IsTypef(t, encryption.X25519KeyPair{}, keyPiar2, "keyPiar2 is not of type encryption.KeyPair")
	specs := encryption.CipherKeySpecs{
		Salt:            "some_salt",
		Iterations:      "5000",
		SharedPublicKey: keyPiar2.PublicKey,
		PrivateKey:      keyPiar1.PrivateKey,
		Algo:            encryption.XChaCha20_Poly1305_PBKDF2_Curve25519,
	}

	plainData := []byte("This is a test.")
	encryptedData, err := encryption.ChaChaEncrypt(plainData, specs)
	require.NoError(t, err)
	require.NotNil(t, encryptedData)

	decryptedData, err := encryption.ChaChaDecrypt(encryptedData, specs)
	require.NoError(t, err)
	require.NotNil(t, decryptedData)

	// The decrypted data should be equal to the original plain data
	require.Equal(t, decryptedData, plainData)
	require.NotEqual(t, encryptedData, plainData)
}

// TestChaChaDecryptError verifies that an error is returned when decrypting with an incorrect cipher text.
func TestChaChaDecryptError(t *testing.T) {
	keyPiar1, err := encryption.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPiar1)
	require.IsTypef(t, encryption.X25519KeyPair{}, keyPiar1, "keyPiar1 is not of type encryption.KeyPair")
	specs := encryption.CipherKeySpecs{
		Salt:            "some_salt",
		Iterations:      "5000",
		SharedPublicKey: keyPiar1.PublicKey,
		PrivateKey:      keyPiar1.PrivateKey,
		Algo:            encryption.XChaCha20_Poly1305_PBKDF2_Curve25519,
	}

	// Encrypted data that is too short to be valid
	encryptedData := []byte("short")

	_, err = encryption.ChaChaDecrypt(encryptedData, specs)
	require.Error(t, err)
}
