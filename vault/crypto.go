package vault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Envelope contains encrypted payload metadata for transport.
type Envelope struct {
	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`
}

// Encrypt uses XChaCha20-Poly1305 to encrypt plaintext using aad binding.
func Encrypt(encKey [32]byte, plaintext, aad []byte) (Envelope, error) {
	aead, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return Envelope{
		NonceB64: base64.StdEncoding.EncodeToString(nonce),
		CTB64:    base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Decrypt reverses Encrypt.
func Decrypt(encKey [32]byte, env Envelope, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.NonceB64)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid nonce size")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CTB64)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, aad)
}
