package vault

import (
	"context"
	"database/sql"
	"strconv"

	_ "modernc.org/sqlite"
)

// Store persists encrypted changes and sync state locally.
type Store struct {
	db *sql.DB
}

// OpenStore opens/creates a SQLite database and runs migrations.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS outbox (
  change_id TEXT PRIMARY KEY,
  entity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  op TEXT NOT NULL,
  ts INTEGER NOT NULL,
  aad TEXT NOT NULL,
  nonce_b64 TEXT NOT NULL,
  ct_b64 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applied (
  change_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sync_state (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`)
	return err
}

// EnqueueEncryptedChange writes a ready-to-push encrypted envelope.
func (s *Store) EnqueueEncryptedChange(ctx context.Context, c Change, userID, deviceID string, env Envelope) error {
	aad := string(c.AAD(userID, deviceID))
	_, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO outbox(change_id, entity, entity_id, op, ts, aad, nonce_b64, ct_b64)
VALUES(?,?,?,?,?,?,?,?)`,
		c.ChangeID, c.Entity, c.EntityID, string(c.Op), c.TS.Unix(), aad, env.NonceB64, env.CTB64,
	)
	return err
}

// OutboxItem is a queued envelope plus metadata needed for push.
type OutboxItem struct {
	ChangeID string
	Entity   string
	TS       int64
	Env      Envelope
}

// DequeueBatch returns envelopes up to limit.
func (s *Store) DequeueBatch(ctx context.Context, limit int) ([]OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT change_id, entity, ts, nonce_b64, ct_b64 FROM outbox ORDER BY ts ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var items []OutboxItem
	for rows.Next() {
		var it OutboxItem
		if err := rows.Scan(&it.ChangeID, &it.Entity, &it.TS, &it.Env.NonceB64, &it.Env.CTB64); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// AckOutbox removes acknowledged changes.
func (s *Store) AckOutbox(ctx context.Context, changeIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	stmt, err := tx.PrepareContext(ctx, `DELETE FROM outbox WHERE change_id = ?`)
	if err != nil {
		return err
	}
	defer func() {
		_ = stmt.Close()
	}()

	for _, id := range changeIDs {
		if _, err := stmt.ExecContext(ctx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetState fetches sync metadata with default fallback.
func (s *Store) GetState(ctx context.Context, key, def string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM sync_state WHERE k = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return def, nil
	}
	return v, err
}

// SetState updates sync metadata.
func (s *Store) SetState(ctx context.Context, key, val string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sync_state(k,v) VALUES(?,?)
ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, val)
	return err
}

// PendingCount returns the number of changes waiting to sync.
func (s *Store) PendingCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&count)
	return count, err
}

// SyncStatus contains current sync state.
type SyncStatus struct {
	PendingChanges int
	LastPulledSeq  int64
}

// SyncStatus returns current sync state.
func (s *Store) SyncStatus(ctx context.Context) (SyncStatus, error) {
	pending, err := s.PendingCount(ctx)
	if err != nil {
		return SyncStatus{}, err
	}

	seqStr, err := s.GetState(ctx, "last_pulled_seq", "0")
	if err != nil {
		return SyncStatus{}, err
	}

	seq, _ := strconv.ParseInt(seqStr, 10, 64)

	return SyncStatus{
		PendingChanges: pending,
		LastPulledSeq:  seq,
	}, nil
}
