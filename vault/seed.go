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

// ParseSeedPhrase parses a seed from either BIP39 mnemonic or hex format.
// It auto-detects the format: if it contains spaces, it's treated as mnemonic.
func ParseSeedPhrase(phrase string) (SeedPhrase, error) {
	phrase = strings.TrimSpace(phrase)
	if phrase == "" {
		return SeedPhrase{}, errors.New("seed phrase required")
	}

	// If it contains spaces, try to parse as BIP39 mnemonic
	if strings.Contains(phrase, " ") {
		seed, err := ParseMnemonic(phrase)
		if err != nil {
			return SeedPhrase{}, err
		}
		// BIP39 seed is 64 bytes, take first 32 for our key derivation
		if len(seed) < 32 {
			return SeedPhrase{}, errors.New("mnemonic seed too short")
		}
		return SeedPhrase{Raw: seed[:32]}, nil
	}

	// Otherwise try hex decoding
	b, err := hex.DecodeString(phrase)
	if err != nil {
		return SeedPhrase{}, err
	}
	if len(b) != 32 {
		return SeedPhrase{}, errors.New("seed must decode to 32 bytes")
	}
	return SeedPhrase{Raw: b}, nil
}
