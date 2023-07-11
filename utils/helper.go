package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
)

// SafeStringToInt converts a string to an int
func SafeStringToInt(s string) (int, error) {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("conversion error: %w", err)
	}
	return i, nil
}

func GenerateSalt() (string, error) {
	salt := make([]byte, 64)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(salt), nil
}
