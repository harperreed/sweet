package inspect

import (
	"context"
	"database/sql"
	"errors"

	_ "modernc.org/sqlite"
)

// Inspector provides read-only access to the records table for introspection.
type Inspector struct {
	db *sql.DB
}

// Open opens the SQLite database located at path.
func Open(path string) (*Inspector, error) {
	if path == "" {
		return nil, errors.New("app db path required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	return &Inspector{db: db}, nil
}

// Close releases resources held by Inspector.
func (i *Inspector) Close() error {
	if i == nil || i.db == nil {
		return nil
	}
	return i.db.Close()
}

// SummaryRow represents the count of records per entity.
type SummaryRow struct {
	Entity string
	Count  int
}

// Summary returns per-entity record counts.
func (i *Inspector) Summary(ctx context.Context) ([]SummaryRow, error) {
	rows, err := i.db.QueryContext(ctx, `SELECT entity, COUNT(*) FROM records GROUP BY entity ORDER BY entity`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []SummaryRow
	for rows.Next() {
		var r SummaryRow
		if err := rows.Scan(&r.Entity, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Record captures a single logical record payload.
type Record struct {
	Entity   string
	EntityID string
	Payload  string
	Op       string
	Updated  int64
}

// List returns records for the given entity ordered by updated_at desc.
func (i *Inspector) List(ctx context.Context, entity string, limit int) ([]Record, error) {
	if entity == "" {
		return nil, errors.New("entity required")
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := i.db.QueryContext(ctx, `
SELECT entity, entity_id, payload, op, updated_at
FROM records
WHERE entity = ?
ORDER BY updated_at DESC
LIMIT ?`, entity, limit)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.Entity, &r.EntityID, &r.Payload, &r.Op, &r.Updated); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
