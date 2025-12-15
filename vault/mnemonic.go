// ABOUTME: Provides BIP39 mnemonic phrase generation and parsing for seed backup.
// ABOUTME: Users store mnemonic in password manager for cross-device recovery.
package vault

import (
	"errors"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

// NewMnemonic generates a new 24-word BIP39 mnemonic and derives a 64-byte seed.
// The mnemonic should be displayed to the user for backup in their password manager.
func NewMnemonic() (mnemonic string, seed []byte, err error) {
	entropy, err := bip39.NewEntropy(256) // 256 bits = 24 words
	if err != nil {
		return "", nil, err
	}

	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		return "", nil, err
	}

	// Empty passphrase - user's password manager stores the mnemonic
	seed = bip39.NewSeed(mnemonic, "")
	return mnemonic, seed, nil
}

// ParseMnemonic validates a mnemonic phrase and returns the derived seed.
func ParseMnemonic(mnemonic string) ([]byte, error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if mnemonic == "" {
		return nil, errors.New("mnemonic required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid mnemonic phrase")
	}

	seed := bip39.NewSeed(mnemonic, "")
	return seed, nil
}
