// ABOUTME: Snapshot creation and retrieval for efficient sync bootstrap.
// ABOUTME: Enables compaction of old changes and fast new-device onboarding.

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type snapshotReq struct {
	UserID string   `json:"user_id"`
	Entity string   `json:"entity"`
	Env    envelope `json:"env"`
}

type snapshotResp struct {
	SnapshotID string `json:"snapshot_id"`
	MinSeq     int64  `json:"min_seq"`
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	var req snapshotReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.Entity = strings.TrimSpace(req.Entity)

	if req.UserID != authUser {
		fail(w, http.StatusForbidden, "token user mismatch")
		return
	}
	if req.Entity == "" || req.Env.NonceB64 == "" || req.Env.CTB64 == "" {
		fail(w, http.StatusBadRequest, "entity and env required")
		return
	}

	// Use transaction to prevent race conditions
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Get current max seq for this user/entity
	var maxSeq int64
	err = tx.QueryRowContext(r.Context(), `
SELECT COALESCE(MAX(seq), 0) FROM changes WHERE user_id=? AND entity=?
`, req.UserID, req.Entity).Scan(&maxSeq)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	snapshotID := randHex(16)
	now := time.Now().Unix()

	if _, err := tx.ExecContext(r.Context(), `
INSERT INTO snapshots(snapshot_id, user_id, entity, created_at, min_seq, nonce_b64, ct_b64)
VALUES(?,?,?,?,?,?,?)
`, snapshotID, req.UserID, req.Entity, now, maxSeq, req.Env.NonceB64, req.Env.CTB64); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	if err := tx.Commit(); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, snapshotResp{SnapshotID: snapshotID, MinSeq: maxSeq})
}

type snapshotInfo struct {
	SnapshotID string   `json:"snapshot_id"`
	MinSeq     int64    `json:"min_seq"`
	CreatedAt  int64    `json:"created_at"`
	Env        envelope `json:"env"`
}

func (s *Server) getLatestSnapshot(ctx context.Context, userID, entity string) (*snapshotInfo, error) {
	var info snapshotInfo
	err := s.db.QueryRowContext(ctx, `
SELECT snapshot_id, min_seq, created_at, nonce_b64, ct_b64
FROM snapshots
WHERE user_id=? AND entity=?
ORDER BY created_at DESC
LIMIT 1
`, userID, entity).Scan(&info.SnapshotID, &info.MinSeq, &info.CreatedAt, &info.Env.NonceB64, &info.Env.CTB64)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func (s *Server) handleCompact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	entity := strings.TrimSpace(r.URL.Query().Get("entity"))
	if entity == "" {
		fail(w, http.StatusBadRequest, "entity required")
		return
	}

	// Get latest snapshot's min_seq
	snapshot, err := s.getLatestSnapshot(r.Context(), authUser, entity)
	if err != nil {
		fail(w, http.StatusNotFound, "no snapshot found")
		return
	}

	// Delete changes older than snapshot (exclusive boundary)
	res, err := s.db.ExecContext(r.Context(), `
DELETE FROM changes WHERE user_id=? AND entity=? AND seq < ?
`, authUser, entity, snapshot.MinSeq)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	deleted, _ := res.RowsAffected()
	ok(w, map[string]any{"ok": true, "deleted_changes": deleted})
}
