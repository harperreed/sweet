package vault

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
)

func TestStoreOutboxLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("close store: %v", cerr)
		}
	}()

	change, err := NewChange("todo", "1", OpUpsert, map[string]any{"text": "x"})
	if err != nil {
		t.Fatalf("new change: %v", err)
	}
	env := Envelope{NonceB64: "nonce", CTB64: "cipher"}
	if err := store.EnqueueEncryptedChange(ctx, change, "user", "device", env); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	items, err := store.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].ChangeID != change.ChangeID {
		t.Fatalf("unexpected change id %s", items[0].ChangeID)
	}

	if err := store.AckOutbox(ctx, []string{change.ChangeID}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	items, err = store.DequeueBatch(ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected empty outbox, got %d", len(items))
	}

	if state, err := store.GetState(ctx, "missing", "default"); err != nil || state != "default" {
		t.Fatalf("GetState default: %v %q", err, state)
	}
	if err := store.SetState(ctx, "foo", "bar"); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	if state, err := store.GetState(ctx, "foo", ""); err != nil || state != "bar" {
		t.Fatalf("GetState stored: %v %q", err, state)
	}
}

func TestStore_PendingCount(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Initially empty
	count, err := store.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 pending, got %d", count)
	}

	// Add some changes
	for i := 0; i < 3; i++ {
		change, _ := NewChange("test", strconv.Itoa(i), OpUpsert, map[string]any{"i": i})
		env := Envelope{NonceB64: "n", CTB64: "c"}
		if err := store.EnqueueEncryptedChange(ctx, change, "user", "device", env); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	count, err = store.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 pending, got %d", count)
	}

	// Ack one
	items, _ := store.DequeueBatch(ctx, 1)
	_ = store.AckOutbox(ctx, []string{items[0].ChangeID})

	count, err = store.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 pending after ack, got %d", count)
	}
}

func TestStore_SyncStatus(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Initial status
	status, err := store.SyncStatus(ctx)
	if err != nil {
		t.Fatalf("SyncStatus: %v", err)
	}
	if status.PendingChanges != 0 {
		t.Errorf("expected 0 pending, got %d", status.PendingChanges)
	}
	if status.LastPulledSeq != 0 {
		t.Errorf("expected seq 0, got %d", status.LastPulledSeq)
	}

	// Add a change
	change, _ := NewChange("test", "1", OpUpsert, nil)
	env := Envelope{NonceB64: "n", CTB64: "c"}
	_ = store.EnqueueEncryptedChange(ctx, change, "user", "device", env)

	// Set last pulled seq
	_ = store.SetState(ctx, "last_pulled_seq", "42")

	status, err = store.SyncStatus(ctx)
	if err != nil {
		t.Fatalf("SyncStatus: %v", err)
	}
	if status.PendingChanges != 1 {
		t.Errorf("expected 1 pending, got %d", status.PendingChanges)
	}
	if status.LastPulledSeq != 42 {
		t.Errorf("expected seq 42, got %d", status.LastPulledSeq)
	}
}
