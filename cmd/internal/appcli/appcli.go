package appcli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oklog/ulid/v2"

	"suitesync/vault"
)

// Options wires shared CLI runtime bits.
type Options struct {
	Entity     string
	SeedPhrase string
	Passphrase string
	VaultPath  string
	AppDBPath  string
	DeviceID   string
	ServerURL  string
	AuthToken  string
}

// App glues an entity-specific CLI to the vault library.
type App struct {
	opts   Options
	store  *vault.Store
	appDB  *sql.DB
	keys   vault.Keys
	client *vault.Client
}

// NewApp instantiates store + DB + client using supplied opts.
func NewApp(opts Options) (*App, error) {
	normalized, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}

	seed, err := vault.ParseSeedPhrase(normalized.SeedPhrase)
	if err != nil {
		return nil, err
	}
	keys, err := vault.DeriveKeys(seed, normalized.Passphrase, vault.DefaultKDFParams())
	if err != nil {
		return nil, err
	}

	store, appDB, err := openDatabases(normalized)
	if err != nil {
		return nil, err
	}

	client := vault.NewClient(vault.SyncConfig{
		BaseURL:   normalized.ServerURL,
		DeviceID:  normalized.DeviceID,
		AuthToken: normalized.AuthToken,
	})

	return &App{
		opts:   normalized,
		store:  store,
		appDB:  appDB,
		keys:   keys,
		client: client,
	}, nil
}

// Close releases resources.
func (a *App) Close() error {
	var firstErr error
	if a.store != nil {
		if err := a.store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if a.appDB != nil {
		if err := a.appDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Upsert records or replaces entity payload.
func (a *App) Upsert(ctx context.Context, entityID string, payload map[string]any) error {
	if entityID == "" {
		return errors.New("entity id required")
	}
	return a.queueChange(ctx, entityID, vault.OpUpsert, payload)
}

// Append creates a fresh entity ID per payload and queues append change.
func (a *App) Append(ctx context.Context, payload map[string]any) (string, error) {
	entityID := ulid.Make().String()
	if err := a.queueChange(ctx, entityID, vault.OpAppend, payload); err != nil {
		return "", err
	}
	return entityID, nil
}

// Delete marks a record as deleted.
func (a *App) Delete(ctx context.Context, entityID string) error {
	if entityID == "" {
		return errors.New("entity id required")
	}
	return a.queueChange(ctx, entityID, vault.OpDelete, nil)
}

// Sync pushes pending changes and pulls remote ones.
func (a *App) Sync(ctx context.Context) error {
	if a.opts.ServerURL == "" || a.opts.AuthToken == "" {
		return errors.New("server url and auth token required for sync")
	}
	return vault.Sync(ctx, a.store, a.client, a.keys, a.ApplyChange)
}

// ApplyChange is passed to vault.Sync to mutate local records.
func (a *App) ApplyChange(ctx context.Context, c vault.Change) error {
	if c.Entity != a.opts.Entity {
		return nil
	}
	if c.Op == vault.OpDelete || c.Deleted {
		_, err := a.appDB.ExecContext(ctx, `DELETE FROM records WHERE entity=? AND entity_id=?`, c.Entity, c.EntityID)
		return err
	}
	_, err := a.appDB.ExecContext(ctx, `
INSERT INTO records(entity, entity_id, payload, op, updated_at)
VALUES(?,?,?,?,?)
ON CONFLICT(entity, entity_id) DO UPDATE SET
  payload=excluded.payload,
  op=excluded.op,
  updated_at=excluded.updated_at
`, c.Entity, c.EntityID, string(c.Payload), string(c.Op), c.TS.Unix())
	return err
}

func (a *App) queueChange(ctx context.Context, entityID string, op vault.Op, payload map[string]any) error {
	var body any
	if payload != nil {
		copyPayload := make(map[string]any, len(payload)+1)
		for k, v := range payload {
			copyPayload[k] = v
		}
		copyPayload["updated_at"] = time.Now().UTC().Unix()
		body = copyPayload
	}
	change, err := vault.NewChange(a.opts.Entity, entityID, op, body)
	if err != nil {
		return err
	}
	if op == vault.OpDelete {
		change.Deleted = true
	}

	if err := a.ApplyChange(ctx, change); err != nil {
		return err
	}

	plain, err := json.Marshal(change)
	if err != nil {
		return err
	}
	aad := change.AAD(a.keys.UserID(), a.opts.DeviceID)
	env, err := vault.Encrypt(a.keys.EncKey, plain, aad)
	if err != nil {
		return err
	}
	return a.store.EnqueueEncryptedChange(ctx, change, a.keys.UserID(), a.opts.DeviceID, env)
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}

func migrateAppDB(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS records (
  entity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  payload TEXT,
  op TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(entity, entity_id)
);
`)
	return err
}

// DumpRecords returns all stored records for debugging/tests.
func (a *App) DumpRecords(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.appDB.QueryContext(ctx, `SELECT entity_id, payload, op, updated_at FROM records WHERE entity=? ORDER BY updated_at DESC`, a.opts.Entity)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []map[string]any
	for rows.Next() {
		var entityID, payloadStr, op string
		var ts int64
		if err := rows.Scan(&entityID, &payloadStr, &op, &ts); err != nil {
			return nil, err
		}
		var payload map[string]any
		if payloadStr != "" {
			if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
				return nil, fmt.Errorf("decode payload %s: %w", entityID, err)
			}
		}
		out = append(out, map[string]any{
			"entity_id":  entityID,
			"payload":    payload,
			"op":         op,
			"updated_at": ts,
		})
	}
	return out, rows.Err()
}

func normalizeOptions(opts Options) (Options, error) {
	if opts.Entity == "" {
		return opts, errors.New("entity required")
	}
	if opts.SeedPhrase == "" {
		return opts, errors.New("seed phrase required")
	}
	if opts.DeviceID == "" {
		if host, err := os.Hostname(); err == nil {
			opts.DeviceID = host
		}
	}
	if opts.VaultPath == "" {
		opts.VaultPath = filepath.Join(os.TempDir(), opts.Entity+"-vault.db")
	}
	if opts.AppDBPath == "" {
		opts.AppDBPath = filepath.Join(os.TempDir(), opts.Entity+".db")
	}
	if err := ensureDir(opts.VaultPath); err != nil {
		return opts, err
	}
	if err := ensureDir(opts.AppDBPath); err != nil {
		return opts, err
	}
	return opts, nil
}

func openDatabases(opts Options) (*vault.Store, *sql.DB, error) {
	store, err := vault.OpenStore(opts.VaultPath)
	if err != nil {
		return nil, nil, err
	}
	appDB, err := sql.Open("sqlite", opts.AppDBPath)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	if err := migrateAppDB(appDB); err != nil {
		_ = appDB.Close()
		_ = store.Close()
		return nil, nil, err
	}
	return store, appDB, nil
}
