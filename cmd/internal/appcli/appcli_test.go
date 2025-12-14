// ABOUTME: Tests for appcli application layer.
// ABOUTME: Covers CRUD operations, sync, and conflict detection.

package appcli

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"suitesync/vault"
)

func TestConflictDetection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	app, err := NewTestApp(dir)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	defer func() {
		if closeErr := app.Close(); closeErr != nil {
			t.Errorf("close app: %v", closeErr)
		}
	}()

	t.Run("no_conflict_on_sequential_updates", func(t *testing.T) {
		testNoConflictOnSequentialUpdates(t, ctx, app)
	})

	t.Run("conflict_on_stale_base_version", func(t *testing.T) {
		testConflictOnStaleBaseVersion(t, ctx, app)
	})
}

func testNoConflictOnSequentialUpdates(t *testing.T, ctx context.Context, app *App) {
	t.Helper()

	initialChange := vault.Change{
		Entity:      "test-entity",
		EntityID:    "item-1",
		BaseVersion: 0,
		Payload:     []byte(`{"text":"original"}`),
		Op:          vault.OpUpsert,
		TS:          time.Now().UTC(),
	}

	conflict, err := app.ApplyWithConflictCheck(ctx, initialChange)
	if err != nil {
		t.Fatalf("apply initial: %v", err)
	}
	if conflict != nil {
		t.Fatalf("unexpected conflict on initial change")
	}

	remoteChange := vault.Change{
		Entity:      "test-entity",
		EntityID:    "item-1",
		BaseVersion: 1,
		Payload:     []byte(`{"text":"remote update"}`),
		Op:          vault.OpUpsert,
		TS:          time.Now().UTC(),
	}

	conflict, err = app.ApplyWithConflictCheck(ctx, remoteChange)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if conflict != nil {
		t.Fatalf("unexpected conflict on first remote change")
	}
}

func testConflictOnStaleBaseVersion(t *testing.T, ctx context.Context, app *App) {
	t.Helper()

	staleChange := vault.Change{
		Entity:      "test-entity",
		EntityID:    "item-1",
		BaseVersion: 0,
		Payload:     []byte(`{"text":"stale update"}`),
		Op:          vault.OpUpsert,
		TS:          time.Now().UTC(),
	}

	conflict, err := app.ApplyWithConflictCheck(ctx, staleChange)
	if err != nil {
		t.Fatalf("apply stale: %v", err)
	}
	if conflict == nil {
		t.Fatalf("expected conflict for stale change")
	}
	if conflict.LocalVersion != 2 {
		t.Errorf("expected local version 2, got %d", conflict.LocalVersion)
	}
}

// NewTestApp creates a minimal test app without sync capabilities.
func NewTestApp(dir string) (*App, error) {
	appDBPath := filepath.Join(dir, "app.sqlite")
	appDB, err := sql.Open("sqlite", appDBPath)
	if err != nil {
		return nil, err
	}
	if err := migrateAppDB(appDB); err != nil {
		_ = appDB.Close()
		return nil, err
	}
	return &App{
		appDB: appDB,
		opts:  Options{Entity: "test-entity"},
	}, nil
}
