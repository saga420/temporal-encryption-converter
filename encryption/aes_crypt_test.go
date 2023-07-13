package encryption

import (
	"bytes"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAesComputeSharedSecret(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair should not return an error: %v", err)
	}

	specs := CipherKeySpecs{
		Salt:            "somesalt",
		Iterations:      "10000",
		SharedPublicKey: keyPair.PublicKey,
		PrivateKey:      keyPair.PrivateKey,
		Algo:            AES256_GCM_PBKDF2_Curve25519,
	}

	_, err = ComputeAESSharedSecret(specs)
	if err != nil {
		t.Fatalf("ComputeSharedSecret should not return an error: %v", err)
	}
}

func TestAesGcmEncryptAndDecrypt1(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair should not return an error: %v", err)
	}

	specs := CipherKeySpecs{
		Salt:            "somesalt",
		Iterations:      "10000",
		SharedPublicKey: keyPair.PublicKey,
		PrivateKey:      keyPair.PrivateKey,
		Algo:            AES256_GCM_PBKDF2_Curve25519,
	}

	plainData := []byte("some plain text")
	ciphertext, err := AesGcmEncrypt(plainData, specs)
	if err != nil {
		t.Fatalf("aesGcmEncrypt should not return an error: %v", err)
	}

	decryptedData, err := AesGcmDecrypt(ciphertext, specs)
	if err != nil {
		t.Fatalf("aesGcmDecrypt should not return an error: %v", err)
	}

	if !bytes.Equal(decryptedData, plainData) {
		t.Fatalf("Decrypted data should be equal to the original plain text. Got %s want %s", hex.EncodeToString(decryptedData), hex.EncodeToString(plainData))
	}
}

func TestComputeAESSharedSecret(t *testing.T) {
	t.Run("should return error when key sizes are not correct", func(t *testing.T) {
		specs := CipherKeySpecs{
			SharedPublicKey: "abcdef",
			PrivateKey:      "abcdef",
			Salt:            "abcdef",
			Iterations:      "1000",
		}

		_, err := ComputeAESSharedSecret(specs)
		assert.Error(t, err)
	})

	t.Run("should not return error when parameters are valid", func(t *testing.T) {
		keyPair, _ := GenerateKeyPair()
		specs := CipherKeySpecs{
			SharedPublicKey: keyPair.PublicKey,
			PrivateKey:      keyPair.PrivateKey,
			Salt:            "abcdef",
			Iterations:      "1000",
		}

		_, err := ComputeAESSharedSecret(specs)
		assert.NoError(t, err)
	})
}

func TestAesGcmEncryptAndDecrypt(t *testing.T) {
	t.Run("should not return error when parameters are valid", func(t *testing.T) {
		keyPair, _ := GenerateKeyPair()
		specs := CipherKeySpecs{
			SharedPublicKey: keyPair.PublicKey,
			PrivateKey:      keyPair.PrivateKey,
			Salt:            "abcdef",
			Iterations:      "1000",
		}

		plainText := "Hello, world!"
		encryptedData, err := AesGcmEncrypt([]byte(plainText), specs)
		require.NoError(t, err)

		decryptedData, err := AesGcmDecrypt(encryptedData, specs)
		require.NoError(t, err)

		assert.Equal(t, plainText, string(decryptedData))
	})

	t.Run("should return error when encrypted data is too short", func(t *testing.T) {
		keyPair, _ := GenerateKeyPair()
		specs := CipherKeySpecs{
			SharedPublicKey: keyPair.PublicKey,
			PrivateKey:      keyPair.PrivateKey,
			Salt:            "abcdef",
			Iterations:      "1000",
		}

		shortData, _ := hex.DecodeString("00ff")
		_, err := AesGcmDecrypt(shortData, specs)
		assert.Error(t, err)
	})

	t.Run("should return error when parameters are invalid", func(t *testing.T) {
		invalidSpecs := CipherKeySpecs{
			SharedPublicKey: "invalid",
			PrivateKey:      "invalid",
			Salt:            "abcdef",
			Iterations:      "1000",
		}

		_, err := AesGcmEncrypt([]byte("Hello, world!"), invalidSpecs)
		assert.Error(t, err)

		_, err = AesGcmDecrypt([]byte("Hello, world!"), invalidSpecs)
		assert.Error(t, err)
	})
}
