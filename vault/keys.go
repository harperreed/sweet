package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Keys represents deterministic key material derived from a seed.
type Keys struct {
	EncKey  [32]byte
	UserKey [32]byte
}

// DeriveKeys expands a seed + optional passphrase into subkeys.
func DeriveKeys(seed SeedPhrase, passphrase string, params KDFParams) (Keys, error) {
	input := append([]byte{}, seed.Raw...)
	input = append(input, []byte(passphrase)...)

	salt := []byte("syncvault:v1:argon2id")
	mk := argon2.IDKey(
		input,
		salt,
		params.Time,
		params.MemoryMB*1024,
		params.Threads,
		params.KeyLen,
	)

	var out Keys

	enc := hkdf.New(sha256.New, mk, nil, []byte("syncvault:v1:enc"))
	if _, err := io.ReadFull(enc, out.EncKey[:]); err != nil {
		return Keys{}, err
	}

	uid := hkdf.New(sha256.New, mk, nil, []byte("syncvault:v1:user"))
	if _, err := io.ReadFull(uid, out.UserKey[:]); err != nil {
		return Keys{}, err
	}

	for i := range mk {
		mk[i] = 0
	}
	return out, nil
}

// UserID returns a stable identifier derived from UserKey.
func (k Keys) UserID() string {
	sum := sha256.Sum256(k.UserKey[:])
	return hex.EncodeToString(sum[:16])
}
