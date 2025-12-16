// ABOUTME: Conflict detection for multi-device sync scenarios.
// ABOUTME: Detects when remote changes are based on stale local versions.

package appcli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/harperreed/sweet/vault"
)

// Conflict represents a detected version conflict.
type Conflict struct {
	Entity       string
	EntityID     string
	LocalVersion int64
	LocalPayload json.RawMessage
	RemoteChange vault.Change
}

// ApplyWithConflictCheck applies a change, detecting version conflicts.
// Returns non-nil Conflict if the change's BaseVersion doesn't match local version.
func (a *App) ApplyWithConflictCheck(ctx context.Context, c vault.Change) (*Conflict, error) {
	// Get current local version
	var localVersion int64
	var localPayload string
	err := a.appDB.QueryRowContext(ctx, `
SELECT version, payload FROM records WHERE entity=? AND entity_id=?
`, c.Entity, c.EntityID).Scan(&localVersion, &localPayload)

	if err == sql.ErrNoRows {
		// New record, no conflict possible
		return nil, a.applyChange(ctx, c, 0)
	}
	if err != nil {
		return nil, err
	}

	// Check for conflict: remote change based on different version than local
	// This catches both stale (BaseVersion < localVersion) and future (BaseVersion > localVersion) conflicts
	if c.BaseVersion != localVersion {
		return &Conflict{
			Entity:       c.Entity,
			EntityID:     c.EntityID,
			LocalVersion: localVersion,
			LocalPayload: json.RawMessage(localPayload),
			RemoteChange: c,
		}, nil
	}

	// No conflict, apply the change
	return nil, a.applyChange(ctx, c, localVersion)
}

func (a *App) applyChange(ctx context.Context, c vault.Change, currentVersion int64) error {
	newVersion := currentVersion + 1

	switch c.Op {
	case vault.OpDelete:
		_, err := a.appDB.ExecContext(ctx, `DELETE FROM records WHERE entity=? AND entity_id=?`, c.Entity, c.EntityID)
		return err
	case vault.OpUpsert, vault.OpAppend:
		_, err := a.appDB.ExecContext(ctx, `
INSERT INTO records(entity, entity_id, payload, op, version, updated_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(entity, entity_id) DO UPDATE SET
  payload=excluded.payload,
  op=excluded.op,
  version=excluded.version,
  updated_at=excluded.updated_at
`, c.Entity, c.EntityID, string(c.Payload), string(c.Op), newVersion, c.TS.Unix())
		return err
	default:
		return fmt.Errorf("unknown operation: %s", c.Op)
	}
}

// GetVersion returns the current version of a record (0 if not exists).
func (a *App) GetVersion(ctx context.Context, entity, entityID string) (int64, error) {
	var version int64
	err := a.appDB.QueryRowContext(ctx, `
SELECT version FROM records WHERE entity=? AND entity_id=?
`, entity, entityID).Scan(&version)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return version, err
}
