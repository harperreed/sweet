// ABOUTME: Tests for BIP39 mnemonic phrase generation and parsing.
// ABOUTME: Verifies 24-word mnemonic format and seed derivation consistency.
package vault

import (
	"strings"
	"testing"
)

func TestNewMnemonic(t *testing.T) {
	mnemonic, seed, err := NewMnemonic()
	if err != nil {
		t.Fatalf("NewMnemonic failed: %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		t.Errorf("expected 24 words, got %d", len(words))
	}

	if len(seed) != 64 {
		t.Errorf("expected 64 byte seed, got %d", len(seed))
	}
}

func TestParseMnemonic(t *testing.T) {
	mnemonic, originalSeed, err := NewMnemonic()
	if err != nil {
		t.Fatalf("NewMnemonic failed: %v", err)
	}

	parsedSeed, err := ParseMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("ParseMnemonic failed: %v", err)
	}

	if string(parsedSeed) != string(originalSeed) {
		t.Error("parsed seed does not match original")
	}
}

func TestParseMnemonicInvalid(t *testing.T) {
	_, err := ParseMnemonic("invalid words here")
	if err == nil {
		t.Error("expected error for invalid mnemonic")
	}
}
