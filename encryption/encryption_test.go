package encryption

import (
	"encoding/hex"
	"testing"
)

// TestSafeStringToInt tests the SafeStringToInt function
func TestSafeStringToInt(t *testing.T) {
	input := "123"
	expected := 123

	result, err := SafeStringToInt(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result != expected {
		t.Errorf("incorrect result, got: %d, expected: %d", result, expected)
	}

	input = "abc"

	_, err = SafeStringToInt(input)
	if err == nil {
		t.Error("expected an error, but got nil")
	}
}

// TestGenerateSalt tests the GenerateSalt function
func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	decodedSalt, err := hex.DecodeString(salt)

	if err != nil {
		t.Errorf("failed to decode salt: %v", err)
	}

	if len(decodedSalt) != 64 {
		t.Errorf("incorrect salt length, got: %d, expected: 64", len(decodedSalt))
	}
}
