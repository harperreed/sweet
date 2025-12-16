// ABOUTME: Snapshot creation and retrieval for efficient sync bootstrap.
// ABOUTME: Enables compaction of old changes and fast new-device onboarding.

package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/pocketbase/pocketbase/core"
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

	// Get current max seq for this user/entity
	maxSeq, err := s.getMaxSeqForEntity(req.UserID, req.Entity)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	snapshotID := randHex(16)

	snapshotsCol, err := s.app.FindCollectionByNameOrId("sync_snapshots")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	record := core.NewRecord(snapshotsCol)
	record.Set("snapshot_id", snapshotID)
	record.Set("user_id", req.UserID)
	record.Set("entity", req.Entity)
	record.Set("min_seq", maxSeq)
	record.Set("nonce_b64", req.Env.NonceB64)
	record.Set("ct_b64", req.Env.CTB64)

	if err := s.app.Save(record); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, snapshotResp{SnapshotID: snapshotID, MinSeq: maxSeq})
}

func (s *Server) getMaxSeqForEntity(userID, entity string) (int64, error) {
	changesCol, err := s.app.FindCollectionByNameOrId("sync_changes")
	if err != nil {
		return 0, err
	}
	records, err := s.app.FindRecordsByFilter(changesCol, "user_id = {:user_id} && entity = {:entity}", "-seq", 1, 0,
		map[string]any{"user_id": userID, "entity": entity})
	if err != nil {
		return 0, nil //nolint:nilerr // No records is valid; return 0 seq.
	}
	if len(records) == 0 {
		return 0, nil
	}
	return int64(records[0].GetInt("seq")), nil
}

//nolint:unparam // ctx reserved for future use.
func (s *Server) getLatestSnapshot(_ context.Context, userID, entity string) (*snapshotInfo, error) {
	snapshotsCol, err := s.app.FindCollectionByNameOrId("sync_snapshots")
	if err != nil {
		return nil, err
	}
	records, err := s.app.FindRecordsByFilter(snapshotsCol, "user_id = {:user_id} && entity = {:entity}", "-min_seq", 1, 0,
		map[string]any{"user_id": userID, "entity": entity})
	if err != nil || len(records) == 0 {
		return nil, err
	}

	r := records[0]
	info := &snapshotInfo{
		SnapshotID: r.GetString("snapshot_id"),
		MinSeq:     int64(r.GetInt("min_seq")),
		CreatedAt:  r.GetDateTime("created").Time().Unix(),
		Env: envelope{
			NonceB64: r.GetString("nonce_b64"),
			CTB64:    r.GetString("ct_b64"),
		},
	}
	return info, nil
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
	changesCol, err := s.app.FindCollectionByNameOrId("sync_changes")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	// Delete in batches to handle large datasets
	var deleted int64
	batchSize := 1000
	for {
		toDelete, err := s.app.FindRecordsByFilter(changesCol,
			"user_id = {:user_id} && entity = {:entity} && seq < {:min_seq}", "", batchSize, 0,
			map[string]any{"user_id": authUser, "entity": entity, "min_seq": snapshot.MinSeq})
		if err != nil {
			fail(w, http.StatusInternalServerError, "db error")
			return
		}
		if len(toDelete) == 0 {
			break
		}

		for _, rec := range toDelete {
			if err := s.app.Delete(rec); err != nil {
				log.Printf("compact: failed to delete record %s: %v", rec.Id, err)
			} else {
				deleted++
			}
		}
	}

	ok(w, map[string]any{"ok": true, "deleted": deleted})
}

func (s *Server) handleWipe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	// Delete all sync_changes for this user
	changesCol, err := s.app.FindCollectionByNameOrId("sync_changes")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	// Delete in batches to handle large datasets
	var deleted int
	batchSize := 1000
	for {
		toDelete, err := s.app.FindRecordsByFilter(changesCol,
			"user_id = {:user_id}", "", batchSize, 0,
			map[string]any{"user_id": authUser})
		if err != nil {
			fail(w, http.StatusInternalServerError, "db error")
			return
		}
		if len(toDelete) == 0 {
			break
		}

		for _, rec := range toDelete {
			if err := s.app.Delete(rec); err != nil {
				log.Printf("wipe: failed to delete change %s: %v", rec.Id, err)
			} else {
				deleted++
			}
		}
	}

	// Also delete any snapshots for this user (in batches)
	snapshotsCol, err := s.app.FindCollectionByNameOrId("sync_snapshots")
	if err != nil {
		log.Printf("wipe: sync_snapshots collection not found: %v", err)
	} else {
		for {
			snapshots, err := s.app.FindRecordsByFilter(snapshotsCol,
				"user_id = {:user_id}", "", batchSize, 0,
				map[string]any{"user_id": authUser})
			if err != nil {
				log.Printf("wipe: failed to query snapshots: %v", err)
				break
			}
			if len(snapshots) == 0 {
				break
			}

			for _, rec := range snapshots {
				if err := s.app.Delete(rec); err != nil {
					log.Printf("wipe: failed to delete snapshot %s: %v", rec.Id, err)
				}
			}
		}
	}

	ok(w, map[string]any{"deleted": deleted})
}
