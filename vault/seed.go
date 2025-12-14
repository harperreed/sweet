package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

// SeedPhrase is a simple 32-byte seed encoded to/from a string.
type SeedPhrase struct {
	Raw []byte
}

// NewSeedPhrase produces a new random seed phrase and human string.
func NewSeedPhrase() (SeedPhrase, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return SeedPhrase{}, "", err
	}
	phrase := hex.EncodeToString(b)
	return SeedPhrase{Raw: b}, phrase, nil
}

// ParseSeedPhrase converts the provided hex string back into bytes.
func ParseSeedPhrase(phrase string) (SeedPhrase, error) {
	phrase = strings.TrimSpace(phrase)
	if phrase == "" {
		return SeedPhrase{}, errors.New("seed phrase required")
	}
	b, err := hex.DecodeString(phrase)
	if err != nil {
		return SeedPhrase{}, err
	}
	if len(b) != 32 {
		return SeedPhrase{}, errors.New("seed must decode to 32 bytes")
	}
	return SeedPhrase{Raw: b}, nil
}
