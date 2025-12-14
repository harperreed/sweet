// ABOUTME: Integration tests for seed rotation workflow.
// ABOUTME: Tests end-to-end re-encryption and account migration.

package main

import (
	"encoding/json"
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

func generateTestKeys(t *testing.T) (oldKeys, newKeys vault.Keys) {
	t.Helper()
	oldSeed, _, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("generate old seed: %v", err)
	}
	oldKeys, err = vault.DeriveKeys(oldSeed, "", vault.DefaultKDFParams())
	if err != nil {
		t.Fatalf("derive old keys: %v", err)
	}

	newSeed, _, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("generate new seed: %v", err)
	}
	newKeys, err = vault.DeriveKeys(newSeed, "", vault.DefaultKDFParams())
	if err != nil {
		t.Fatalf("derive new keys: %v", err)
	}
	return oldKeys, newKeys
}

func createEncryptedPullItem(t *testing.T, deviceID string, keys vault.Keys, change vault.Change) vault.PullItem {
	t.Helper()
	changeBytes, err := json.Marshal(change)
	if err != nil {
		t.Fatalf("marshal change: %v", err)
	}
	aad := change.AAD(keys.UserID(), deviceID)
	env, err := vault.Encrypt(keys.EncKey, changeBytes, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return vault.PullItem{
		ChangeID: change.ChangeID,
		Entity:   change.Entity,
		TS:       change.TS.Unix(),
		DeviceID: deviceID,
		Env:      env,
	}
}

func TestReencryptPreservesDeviceID(t *testing.T) {
	oldKeys, newKeys := generateTestKeys(t)

	deviceID := "device-a"
	payload := map[string]string{"key": "test-key", "value": "test-value"}
	change, err := vault.NewChange("doc", "doc-123", vault.OpUpsert, payload)
	if err != nil {
		t.Fatalf("create change: %v", err)
	}

	pullItem := createEncryptedPullItem(t, deviceID, oldKeys, change)

	reencrypted, err := reencryptChanges([]vault.PullItem{pullItem}, oldKeys, newKeys, newKeys.UserID())
	if err != nil {
		t.Fatalf("reencrypt changes: %v", err)
	}

	if len(reencrypted) != 1 {
		t.Fatalf("expected 1 reencrypted item, got %d", len(reencrypted))
	}

	newAAD := change.AAD(newKeys.UserID(), deviceID)
	decrypted, err := vault.Decrypt(newKeys.EncKey, reencrypted[0].Env, newAAD)
	if err != nil {
		t.Fatalf("decrypt after rotation failed: %v (this is the critical bug - device_id mismatch)", err)
	}

	var decryptedChange vault.Change
	if err := json.Unmarshal(decrypted, &decryptedChange); err != nil {
		t.Fatalf("unmarshal decrypted change: %v", err)
	}

	if decryptedChange.ChangeID != change.ChangeID {
		t.Errorf("ChangeID mismatch: expected %s, got %s", change.ChangeID, decryptedChange.ChangeID)
	}
	if decryptedChange.EntityID != change.EntityID {
		t.Errorf("EntityID mismatch: expected %s, got %s", change.EntityID, decryptedChange.EntityID)
	}
	if decryptedChange.Op != change.Op {
		t.Errorf("Op mismatch: expected %s, got %s", change.Op, decryptedChange.Op)
	}
}

func TestReencryptMultipleDevices(t *testing.T) {
	oldKeys, newKeys := generateTestKeys(t)

	devices := []string{"device-a", "device-b", "device-c"}
	pullItems, changes := createMultiDeviceTestData(t, devices, oldKeys)

	reencrypted, err := reencryptChanges(pullItems, oldKeys, newKeys, newKeys.UserID())
	if err != nil {
		t.Fatalf("reencrypt changes: %v", err)
	}

	verifyDevicesCanDecrypt(t, devices, changes, reencrypted, newKeys)
}

func createMultiDeviceTestData(t *testing.T, devices []string, keys vault.Keys) ([]vault.PullItem, []vault.Change) {
	t.Helper()
	pullItems := make([]vault.PullItem, 0, len(devices))
	changes := make([]vault.Change, 0, len(devices))

	for _, deviceID := range devices {
		payload := map[string]string{"device": deviceID, "data": deviceID + "-value"}
		change, err := vault.NewChange("doc", "doc-"+deviceID, vault.OpUpsert, payload)
		if err != nil {
			t.Fatalf("create change for %s: %v", deviceID, err)
		}
		changes = append(changes, change)
		pullItems = append(pullItems, createEncryptedPullItem(t, deviceID, keys, change))
	}
	return pullItems, changes
}

func verifyDevicesCanDecrypt(t *testing.T, devices []string, changes []vault.Change, reencrypted []vault.PushItem, keys vault.Keys) {
	t.Helper()
	for i, deviceID := range devices {
		change := changes[i]
		newAAD := change.AAD(keys.UserID(), deviceID)
		decrypted, err := vault.Decrypt(keys.EncKey, reencrypted[i].Env, newAAD)
		if err != nil {
			t.Fatalf("device %s cannot decrypt after rotation: %v", deviceID, err)
		}

		var decryptedChange vault.Change
		if err := json.Unmarshal(decrypted, &decryptedChange); err != nil {
			t.Fatalf("unmarshal for %s: %v", deviceID, err)
		}

		if decryptedChange.ChangeID != change.ChangeID {
			t.Errorf("device %s: ChangeID mismatch", deviceID)
		}
		if decryptedChange.EntityID != change.EntityID {
			t.Errorf("device %s: EntityID mismatch", deviceID)
		}
	}
}
