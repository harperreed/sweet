package vault

import "testing"

func TestSeedPhraseRoundTrip(t *testing.T) {
	seed, phrase, err := NewSeedPhrase()
	if err != nil {
		t.Fatalf("new seed: %v", err)
	}
	parsed, err := ParseSeedPhrase(phrase)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Raw) != len(seed.Raw) {
		t.Fatalf("expected %d bytes, got %d", len(seed.Raw), len(parsed.Raw))
	}
	for i := range seed.Raw {
		if seed.Raw[i] != parsed.Raw[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}

func TestParseSeedPhraseErrors(t *testing.T) {
	if _, err := ParseSeedPhrase(""); err == nil {
		t.Fatalf("expected error for empty phrase")
	}
	if _, err := ParseSeedPhrase("zzzz"); err == nil {
		t.Fatalf("expected error for invalid hex")
	}
	if _, err := ParseSeedPhrase("00"); err == nil {
		t.Fatalf("expected error for short seed")
	}
}
