// ABOUTME: Tests for key/value store using vault library with encryption.
// ABOUTME: Validates set/get/list/delete operations using appcli infrastructure.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"suitesync/cmd/internal/appcli"
	"suitesync/vault"
)

func TestKVSetAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	seed, seedPhrase := generateTestSeed(t)

	appDB := filepath.Join(tmpDir, "app.db")
	vaultDB := filepath.Join(tmpDir, "vault.db")

	if err := kvSet([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "-user-id", "test-user-id", "testkey", "testvalue"}); err != nil {
		t.Fatalf("kvSet failed: %v", err)
	}

	app := openTestApp(t, seed, appDB, vaultDB)
	defer func() { _ = app.Close() }()

	records, err := app.DumpRecords(context.Background())
	if err != nil {
		t.Fatalf("DumpRecords failed: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec["entity_id"] != "testkey" {
		t.Errorf("expected entity_id 'testkey', got %v", rec["entity_id"])
	}

	payload, ok := rec["payload"].(map[string]any)
	if !ok {
		t.Fatalf("invalid payload format")
	}

	if payload["value"] != "testvalue" {
		t.Errorf("expected value 'testvalue', got %v", payload["value"])
	}
}

func TestKVSetUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	_, seedPhrase := generateTestSeed(t)

	appDB := filepath.Join(tmpDir, "app.db")
	vaultDB := filepath.Join(tmpDir, "vault.db")

	if err := kvSet([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "-user-id", "test-user-id", "updatekey", "original"}); err != nil {
		t.Fatalf("first kvSet failed: %v", err)
	}

	if err := kvSet([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "-user-id", "test-user-id", "updatekey", "updated"}); err != nil {
		t.Fatalf("second kvSet failed: %v", err)
	}

	var buf bytes.Buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := kvGet([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "updatekey"})

	_ = w.Close()
	os.Stdout = oldStdout
	_, _ = buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("kvGet failed: %v", err)
	}

	value := strings.TrimSpace(buf.String())
	if value != "updated" {
		t.Errorf("expected value 'updated', got '%s'", value)
	}
}

func TestKVGetNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	_, seedPhrase := generateTestSeed(t)

	appDB := filepath.Join(tmpDir, "app.db")
	vaultDB := filepath.Join(tmpDir, "vault.db")

	err := kvGet([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "nonexistent"})
	if err == nil {
		t.Fatal("expected error for non-existent key, got nil")
	}
	if !strings.Contains(err.Error(), "key not found") {
		t.Errorf("expected 'key not found' error, got: %v", err)
	}
}

func TestKVList(t *testing.T) {
	tmpDir := t.TempDir()
	_, seedPhrase := generateTestSeed(t)

	appDB := filepath.Join(tmpDir, "app.db")
	vaultDB := filepath.Join(tmpDir, "vault.db")

	keys := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	for k, v := range keys {
		if err := kvSet([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "-user-id", "test-user-id", k, v}); err != nil {
			t.Fatalf("kvSet failed for %s: %v", k, err)
		}
	}

	if err := kvList([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB}); err != nil {
		t.Fatalf("kvList failed: %v", err)
	}
}

func TestKVDelete(t *testing.T) {
	tmpDir := t.TempDir()
	seed, seedPhrase := generateTestSeed(t)

	appDB := filepath.Join(tmpDir, "app.db")
	vaultDB := filepath.Join(tmpDir, "vault.db")

	if err := kvSet([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "-user-id", "test-user-id", "deletekey", "deletevalue"}); err != nil {
		t.Fatalf("kvSet failed: %v", err)
	}

	if err := kvDelete([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "-user-id", "test-user-id", "deletekey"}); err != nil {
		t.Fatalf("kvDelete failed: %v", err)
	}

	app := openTestApp(t, seed, appDB, vaultDB)
	defer func() { _ = app.Close() }()

	records, err := app.DumpRecords(context.Background())
	if err != nil {
		t.Fatalf("DumpRecords failed: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("expected 0 records after delete, got %d", len(records))
	}
}

func TestKVListEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	_, seedPhrase := generateTestSeed(t)

	appDB := filepath.Join(tmpDir, "app.db")
	vaultDB := filepath.Join(tmpDir, "vault.db")

	if err := kvList([]string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB}); err != nil {
		t.Fatalf("kvList failed on empty db: %v", err)
	}
}

func TestKVInvalidArguments(t *testing.T) {
	tmpDir := t.TempDir()
	_, seedPhrase := generateTestSeed(t)

	appDB := filepath.Join(tmpDir, "app.db")
	vaultDB := filepath.Join(tmpDir, "vault.db")

	tests := []struct {
		name string
		fn   func([]string) error
		args []string
	}{
		{"set missing value", kvSet, []string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB, "key"}},
		{"get missing key", kvGet, []string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB}},
		{"delete missing key", kvDelete, []string{"-seed", seedPhrase, "-app-db", appDB, "-vault-db", vaultDB}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn(tt.args)
			if err == nil {
				t.Errorf("expected error for invalid arguments, got nil")
			}
		})
	}
}

func generateTestSeed(t *testing.T) (vault.SeedPhrase, string) {
	t.Helper()
	seed, phrase, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("generate seed: %v", err)
	}
	return seed, phrase
}

func openTestApp(t *testing.T, seed vault.SeedPhrase, appDB, vaultDB string) *appcli.App {
	t.Helper()

	app, err := appcli.NewApp(appcli.Options{
		AppID:      sweetAppID,
		Entity:     kvEntity,
		SeedPhrase: hex.EncodeToString(seed.Raw),
		VaultPath:  vaultDB,
		AppDBPath:  appDB,
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	return app
}
