package vault

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSyncerQueueChangePrefixesEntity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Create store
	store, err := OpenStore(filepath.Join(dir, "syncer.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	// Create keys
	seed := SeedPhrase{Raw: bytes32(0x42)}
	params := DefaultKDFParams()
	params.Time = 1
	params.MemoryMB = 32
	keys, err := DeriveKeys(seed, "", params)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	// Create client with AppID
	appID := "550e8400-e29b-41d4-a716-446655440000"
	client := NewClient(SyncConfig{
		AppID:     appID,
		BaseURL:   "https://example.com",
		DeviceID:  "dev-test",
		AuthToken: "token",
	})

	// Create syncer
	syncer := NewSyncer(store, client, keys, keys.UserID())

	// Queue a change with unprefixed entity
	entity := "todo"
	entityID := "task-1"
	payload := map[string]any{"text": "buy milk"}

	_, err = syncer.QueueChange(ctx, entity, entityID, OpUpsert, payload)
	if err != nil {
		t.Fatalf("queue change: %v", err)
	}

	// Dequeue and verify entity is prefixed
	items, err := store.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	expectedEntity := appID + ".todo"
	if items[0].Entity != expectedEntity {
		t.Errorf("expected entity=%q, got %q", expectedEntity, items[0].Entity)
	}
}

func TestSyncerQueueChangeIncludesPrefixInAAD(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	store, err := OpenStore(filepath.Join(dir, "syncer_aad.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	seed := SeedPhrase{Raw: bytes32(0x99)}
	params := DefaultKDFParams()
	params.Time = 1
	params.MemoryMB = 32
	keys, err := DeriveKeys(seed, "", params)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	appID := "a1b2c3d4-e5f6-4789-a012-3456789abcde"
	client := NewClient(SyncConfig{
		AppID:     appID,
		BaseURL:   "https://test.com",
		DeviceID:  "device-x",
		AuthToken: "tok",
	})

	syncer := NewSyncer(store, client, keys, keys.UserID())

	// Queue change
	_, err = syncer.QueueChange(ctx, "item", "id-1", OpUpsert, map[string]any{"value": 42})
	if err != nil {
		t.Fatalf("queue: %v", err)
	}

	// Get the AAD from store (it's stored in the outbox table)
	var storedAAD string
	err = store.db.QueryRow("SELECT aad FROM outbox LIMIT 1").Scan(&storedAAD)
	if err != nil {
		t.Fatalf("query aad: %v", err)
	}

	// AAD should contain the prefixed entity
	prefixedEntity := appID + ".item"
	expectedAADSuffix := "|" + prefixedEntity

	if len(storedAAD) < len(expectedAADSuffix) || storedAAD[len(storedAAD)-len(expectedAADSuffix):] != expectedAADSuffix {
		t.Errorf("AAD should end with %q, got %q", expectedAADSuffix, storedAAD)
	}
}

func TestSyncerQueueChangeMultipleEntities(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	store, err := OpenStore(filepath.Join(dir, "multi.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	seed := SeedPhrase{Raw: bytes32(0x11)}
	params := DefaultKDFParams()
	params.Time = 1
	params.MemoryMB = 32
	keys, err := DeriveKeys(seed, "", params)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	appID := "12345678-1234-1234-1234-123456789abc"
	client := NewClient(SyncConfig{
		AppID:     appID,
		BaseURL:   "https://multi.test",
		DeviceID:  "dev-m",
		AuthToken: "t",
	})

	syncer := NewSyncer(store, client, keys, keys.UserID())

	// Queue multiple different entity types
	entities := []string{"todo", "note", "bookmark", "tag"}
	for i, entity := range entities {
		_, err = syncer.QueueChange(ctx, entity, entity+"-"+string(rune('0'+i)), OpUpsert, map[string]any{"n": i})
		if err != nil {
			t.Fatalf("queue %s: %v", entity, err)
		}
	}

	// Verify all are prefixed
	items, err := store.DequeueBatch(ctx, 100)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}

	if len(items) != len(entities) {
		t.Fatalf("expected %d items, got %d", len(entities), len(items))
	}

	for i, item := range items {
		expected := appID + "." + entities[i]
		if item.Entity != expected {
			t.Errorf("item %d: expected %q, got %q", i, expected, item.Entity)
		}
	}
}
