// ABOUTME: Tests for appcli application layer.
// ABOUTME: Covers CRUD operations, sync, and conflict detection.

package appcli

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/harperreed/sweet/vault"
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

	t.Run("conflict_on_future_base_version", func(t *testing.T) {
		testConflictOnFutureBaseVersion(t, ctx, app)
	})
}

func TestApplyChangeVersionTracking(t *testing.T) {
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

	entityID := "test-item"

	testApplyChangeIncrementsVersion(t, ctx, app, entityID, "first", 1)
	testApplyChangeIncrementsVersion(t, ctx, app, entityID, "second", 2)
	testApplyChangeIncrementsVersion(t, ctx, app, entityID, "third", 3)
}

func testApplyChangeIncrementsVersion(t *testing.T, ctx context.Context, app *App, entityID, text string, expectedVersion int64) {
	t.Helper()

	change := vault.Change{
		Entity:   "test-entity",
		EntityID: entityID,
		Payload:  []byte(`{"text":"` + text + `"}`),
		Op:       vault.OpUpsert,
		TS:       time.Now().UTC(),
	}

	if err := app.ApplyChange(ctx, change); err != nil {
		t.Fatalf("apply change: %v", err)
	}

	version, err := app.GetVersion(ctx, "test-entity", entityID)
	if err != nil {
		t.Fatalf("get version: %v", err)
	}
	if version != expectedVersion {
		t.Errorf("expected version %d, got %d", expectedVersion, version)
	}
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

func testConflictOnFutureBaseVersion(t *testing.T, ctx context.Context, app *App) {
	t.Helper()

	// Create a record with version 1
	initialChange := vault.Change{
		Entity:      "test-entity",
		EntityID:    "item-2",
		BaseVersion: 0,
		Payload:     []byte(`{"text":"initial"}`),
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

	// Now try to apply a change with BaseVersion=10 (future version)
	futureChange := vault.Change{
		Entity:      "test-entity",
		EntityID:    "item-2",
		BaseVersion: 10,
		Payload:     []byte(`{"text":"from the future"}`),
		Op:          vault.OpUpsert,
		TS:          time.Now().UTC(),
	}

	conflict, err = app.ApplyWithConflictCheck(ctx, futureChange)
	if err != nil {
		t.Fatalf("apply future: %v", err)
	}
	if conflict == nil {
		t.Fatalf("expected conflict for future base version")
	}
	if conflict.LocalVersion != 1 {
		t.Errorf("expected local version 1, got %d", conflict.LocalVersion)
	}
}

func TestUnknownOperationErrors(t *testing.T) {
	ctx := context.Background()
	app, closeApp := newTestAppForUnknownOps(t)
	defer closeApp()

	t.Run("applyChange_rejects_unknown_operation", func(t *testing.T) {
		testApplyChangeUnknownOp(t, ctx, app)
	})

	t.Run("ApplyChange_rejects_unknown_operation", func(t *testing.T) {
		testApplyChangePublicUnknownOp(t, ctx, app)
	})

	t.Run("ApplyWithConflictCheck_rejects_unknown_operation", func(t *testing.T) {
		testApplyWithConflictCheckUnknownOp(t, ctx, app)
	})
}

func newTestAppForUnknownOps(t *testing.T) (*App, func()) {
	t.Helper()
	dir := t.TempDir()
	app, err := NewTestApp(dir)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	return app, func() {
		if closeErr := app.Close(); closeErr != nil {
			t.Errorf("close app: %v", closeErr)
		}
	}
}

func testApplyChangeUnknownOp(t *testing.T, ctx context.Context, app *App) {
	t.Helper()
	err := app.applyChange(ctx, vault.Change{
		Entity: "test-entity", EntityID: "test-id",
		Op: vault.Op("unknown-op"), TS: time.Now().UTC(),
	}, 0)
	if err == nil {
		t.Fatal("expected error for unknown operation, got nil")
	}
	if err.Error() != "unknown operation: unknown-op" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func testApplyChangePublicUnknownOp(t *testing.T, ctx context.Context, app *App) {
	t.Helper()
	err := app.ApplyChange(ctx, vault.Change{
		Entity: "test-entity", EntityID: "test-id",
		Op: vault.Op("unknown-op"), Payload: []byte(`{"test":"data"}`), TS: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected error for unknown operation, got nil")
	}
	if err.Error() != "unknown operation: unknown-op" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func testApplyWithConflictCheckUnknownOp(t *testing.T, ctx context.Context, app *App) {
	t.Helper()
	conflict, err := app.ApplyWithConflictCheck(ctx, vault.Change{
		Entity: "test-entity", EntityID: "test-id-2", BaseVersion: 0,
		Op: vault.Op("invalid-op"), Payload: []byte(`{"test":"data"}`), TS: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected error for unknown operation, got nil")
	}
	if conflict != nil {
		t.Fatal("expected nil conflict when error occurs")
	}
	if err.Error() != "unknown operation: invalid-op" {
		t.Errorf("unexpected error message: %v", err)
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
