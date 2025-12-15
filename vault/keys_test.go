package vault

import "testing"

func TestDeriveKeysDeterministic(t *testing.T) {
	seed := SeedPhrase{Raw: bytes32(0x01)}
	params := DefaultKDFParams()
	params.Time = 1
	params.MemoryMB = 32

	keys1, err := DeriveKeys(seed, "", params)
	if err != nil {
		t.Fatalf("derive1: %v", err)
	}
	keys2, err := DeriveKeys(seed, "", params)
	if err != nil {
		t.Fatalf("derive2: %v", err)
	}
	if keys1 != keys2 {
		t.Fatalf("expected deterministic keys")
	}

	keys3, err := DeriveKeys(seed, "pass", params)
	if err != nil {
		t.Fatalf("derive3: %v", err)
	}
	if keys1 == keys3 {
		t.Fatalf("expected different keys with passphrase")
	}
}

func TestUserIDDifferentSeeds(t *testing.T) {
	params := DefaultKDFParams()
	params.Time = 1
	params.MemoryMB = 32

	s1 := SeedPhrase{Raw: bytes32(0xAA)}
	s2 := SeedPhrase{Raw: bytes32(0xAB)}

	k1, err := DeriveKeys(s1, "", params)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	k2, err := DeriveKeys(s2, "", params)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if k1.UserID() == k2.UserID() {
		t.Fatalf("expected different user IDs")
	}
}

func TestDeriveAppKey(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	sweetKey, err := DeriveAppKey(seed, "sweet")
	if err != nil {
		t.Fatalf("DeriveAppKey failed: %v", err)
	}

	todoKey, err := DeriveAppKey(seed, "todo")
	if err != nil {
		t.Fatalf("DeriveAppKey failed: %v", err)
	}

	if len(sweetKey) != 32 {
		t.Errorf("expected 32 byte key, got %d", len(sweetKey))
	}

	// Different apps must get different keys
	if string(sweetKey) == string(todoKey) {
		t.Error("different apps should derive different keys")
	}
}

func TestDeriveAppKeySameAppSameKey(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	key1, err := DeriveAppKey(seed, "sweet")
	if err != nil {
		t.Fatalf("DeriveAppKey failed: %v", err)
	}
	key2, err := DeriveAppKey(seed, "sweet")
	if err != nil {
		t.Fatalf("DeriveAppKey failed: %v", err)
	}

	if string(key1) != string(key2) {
		t.Error("same app should derive same key")
	}
}

func TestDeriveAppKeyEmptySeed(t *testing.T) {
	// Test with nil seed
	_, err := DeriveAppKey(nil, "sweet")
	if err == nil {
		t.Error("expected error when seed is nil")
	}

	// Test with empty seed
	_, err = DeriveAppKey([]byte{}, "sweet")
	if err == nil {
		t.Error("expected error when seed is empty")
	}
}

func TestDeriveAppKeyEmptyAppID(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	_, err := DeriveAppKey(seed, "")
	if err == nil {
		t.Error("expected error when appID is empty")
	}
}

func TestDeriveAppKeyDifferentSeeds(t *testing.T) {
	seed1 := make([]byte, 64)
	for i := range seed1 {
		seed1[i] = byte(i)
	}

	seed2 := make([]byte, 64)
	for i := range seed2 {
		seed2[i] = byte(i + 1)
	}

	key1, err := DeriveAppKey(seed1, "sweet")
	if err != nil {
		t.Fatalf("DeriveAppKey with seed1 failed: %v", err)
	}

	key2, err := DeriveAppKey(seed2, "sweet")
	if err != nil {
		t.Fatalf("DeriveAppKey with seed2 failed: %v", err)
	}

	if string(key1) == string(key2) {
		t.Error("different seeds should derive different keys for same app")
	}
}

func bytes32(fill byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return b
}
