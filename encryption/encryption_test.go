package encryption

import (
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	pubKey, err := hex.DecodeString(keyPair.PublicKey)
	require.NoError(t, err)
	require.Equal(t, len(pubKey), curve25519.PointSize)

	privKey, err := hex.DecodeString(keyPair.PrivateKey)
	require.NoError(t, err)
	require.Equal(t, len(privKey), curve25519.ScalarSize)
}

func TestComputeX25519SharedKey(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	require.NoError(t, err)

	keyPair2, err := GenerateKeyPair()
	require.NoError(t, err)

	secret1, err := ComputeX25519SharedKey(keyPair1.PublicKey, keyPair2.PrivateKey)
	require.NoError(t, err)

	secret2, err := ComputeX25519SharedKey(keyPair2.PublicKey, keyPair1.PrivateKey)
	require.NoError(t, err)

	require.Equal(t, secret1, secret2)
}

func TestSafeStringToInt(t *testing.T) {

	num, err := SafeStringToInt("12345")
	require.NoError(t, err)
	require.Equal(t, num, 12345)

	_, err = SafeStringToInt("not a number")
	require.Error(t, err)
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	require.NoError(t, err)

	saltBytes, err := hex.DecodeString(salt)
	require.NoError(t, err)
	require.Equal(t, len(saltBytes), 64)
}

func TestParsePBKDF2Iterations(t *testing.T) {

	num := ParsePBKDF2Iterations("5000")
	require.Equal(t, num, 5000)

	num = ParsePBKDF2Iterations("8000001")
	require.Equal(t, num, 8000000)

	num = ParsePBKDF2Iterations("4095")
	require.Equal(t, num, 4096)

	num = ParsePBKDF2Iterations("not a number")
	require.Equal(t, num, 4096)
}
