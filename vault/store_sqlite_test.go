package vault

import (
	"context"
	"path/filepath"
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
