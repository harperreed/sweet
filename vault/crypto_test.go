package vault

import "testing"

func TestEncryptDecrypt(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	aad := []byte("aad")
	msg := []byte("secret")

	env, err := Encrypt(key, msg, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plain, err := Decrypt(key, env, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != string(msg) {
		t.Fatalf("expected %q got %q", msg, plain)
	}

	env.CTB64 = env.CTB64[:len(env.CTB64)-2] + "ab" // corrupt ciphertext
	if _, err := Decrypt(key, env, aad); err == nil {
		t.Fatalf("expected decrypt failure on tamper")
	}
}
