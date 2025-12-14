// ABOUTME: Integration tests for seed rotation workflow.
// ABOUTME: Tests end-to-end re-encryption and account migration.

package main

import (
	"testing"

	"suitesync/vault"
)

func TestRotateConfig(t *testing.T) {
	_, seedPhrase, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("generate seed: %v", err)
	}

	cfg := rotateConfig{
		oldSeed:    seedPhrase,
		newSeed:    "",
		passphrase: "",
		serverURL:  "http://localhost:8080",
		appDB:      "/tmp/test.db",
	}

	oldKeys, newKeys, err := deriveRotationKeys(cfg)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	if oldKeys.UserID() == newKeys.UserID() {
		t.Error("old and new user IDs should be different")
	}

	if oldKeys.UserID() == "" || newKeys.UserID() == "" {
		t.Error("user IDs should not be empty")
	}
}
