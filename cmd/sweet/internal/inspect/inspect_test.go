package inspect

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSummaryAndList(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE records(entity TEXT, entity_id TEXT, payload TEXT, op TEXT, updated_at INTEGER)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	inserts := []struct {
		entity, id, payload string
	}{
		{"todo", "1", `{"text":"a"}`},
		{"todo", "2", `{"text":"b"}`},
		{"note", "n1", `{"body":"x"}`},
	}
	for _, in := range inserts {
		if _, err := db.Exec(`INSERT INTO records(entity, entity_id, payload, op, updated_at) VALUES(?,?,?,?,1)`, in.entity, in.id, in.payload, "upsert"); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	_ = db.Close()

	insp, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open inspector: %v", err)
	}
	defer func() {
		if cerr := insp.Close(); cerr != nil {
			t.Fatalf("close inspector: %v", cerr)
		}
	}()

	summary, err := insp.Summary(ctx)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if len(summary) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(summary))
	}

	todos, err := insp.List(ctx, "todo", 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(todos) != 2 {
		t.Fatalf("expected 2 todos, got %d", len(todos))
	}
	if todos[0].Entity != "todo" || todos[0].EntityID == "" {
		t.Fatalf("unexpected record %+v", todos[0])
	}
}
