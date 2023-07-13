package encryption_test

import (
	"github.com/saga420/temporal-encryption-converter/encryption"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGenerateKeyPair tests the GenerateKeyPair function
func TestComputeAESSharedSecret(t *testing.T) {
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
		Algo:            encryption.AES256_GCM_PBKDF2_Curve25519,
	}

	sharedSecret, err := encryption.ComputeAESSharedSecret(specs)
	require.NoError(t, err)
	require.NotNil(t, sharedSecret)
}

// TestGenerateKeyPair tests the GenerateKeyPair function
func TestAesGcmEncrypt(t *testing.T) {
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
		Algo:            encryption.AES256_GCM_PBKDF2_Curve25519,
	}

	plainData := []byte("This is a test.")
	encryptedData, err := encryption.AesGcmEncrypt(plainData, specs)
	require.NoError(t, err)

	// The encrypted data should not be equal to the plain data
	require.NotEqual(t, encryptedData, plainData)
}

// TestGenerateKeyPair tests the GenerateKeyPair function
func TestAesGcmEncryptError(t *testing.T) {
	specs := encryption.CipherKeySpecs{
		Salt:            "some_salt",
		Iterations:      "5000",
		SharedPublicKey: "xx",
		PrivateKey:      "cc",
		Algo:            encryption.AES256_GCM_PBKDF2_Curve25519,
	}

	plainData := []byte("This is a test.")
	encryptedData, err := encryption.AesGcmEncrypt(plainData, specs)
	require.Error(t, err)

	// The encrypted data should not be equal to the plain data
	require.NotEqual(t, encryptedData, plainData)
}

// TestGenerateKeyPair tests the GenerateKeyPair function
func TestAesGcmDecrypt(t *testing.T) {
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
		Algo:            encryption.AES256_GCM_PBKDF2_Curve25519,
	}

	plainData := []byte("This is a test.")
	encryptedData, err := encryption.AesGcmEncrypt(plainData, specs)
	require.NoError(t, err)

	decryptedData, err := encryption.AesGcmDecrypt(encryptedData, specs)
	require.NoError(t, err)

	// The decrypted data should be equal to the original plain data
	require.Equal(t, decryptedData, plainData)
}

// TestGenerateKeyPair tests the GenerateKeyPair function
func TestAesGcmDecryptError(t *testing.T) {
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
		Algo:            encryption.AES256_GCM_PBKDF2_Curve25519,
	}

	// Encrypted data that is too short to be valid
	encryptedData := []byte("short")

	decryptedData, err := encryption.AesGcmDecrypt(encryptedData, specs)
	require.Error(t, err)
	require.Nil(t, decryptedData)
}
