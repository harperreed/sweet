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

func bytes32(fill byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return b
}
