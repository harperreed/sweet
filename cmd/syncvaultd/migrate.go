// ABOUTME: Account migration endpoint for seed rotation.
// ABOUTME: Transfers devices and invalidates old tokens when user rotates their seed.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type migrateReq struct {
	OldUserID string `json:"old_user_id"`
	NewUserID string `json:"new_user_id"`
	Confirm   bool   `json:"confirm"`
}

type migrateResp struct {
	OK              bool  `json:"ok"`
	MigratedDevices int64 `json:"migrated_devices"`
}

func (s *Server) handleMigrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	req, err := parseMigrateRequest(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.OldUserID != authUser {
		fail(w, http.StatusForbidden, "token user mismatch")
		return
	}

	migratedDevices, err := s.executeMigration(r.Context(), req)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}

	ok(w, migrateResp{OK: true, MigratedDevices: migratedDevices})
}

func parseMigrateRequest(r *http.Request) (migrateReq, error) {
	var req migrateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, err
	}
	req.OldUserID = strings.TrimSpace(req.OldUserID)
	req.NewUserID = strings.TrimSpace(req.NewUserID)

	if req.NewUserID == "" {
		return req, fmt.Errorf("new_user_id required")
	}
	if !req.Confirm {
		return req, fmt.Errorf("confirm required")
	}
	return req, nil
}

func (s *Server) executeMigration(ctx context.Context, req migrateReq) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	now := time.Now().Unix()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO users(user_id, created_at) VALUES(?, ?)`, req.NewUserID, now); err != nil {
		return 0, err
	}

	res, err := tx.Exec(`UPDATE devices SET user_id=? WHERE user_id=?`, req.NewUserID, req.OldUserID)
	if err != nil {
		return 0, err
	}
	migratedDevices, _ := res.RowsAffected()

	if _, err := tx.Exec(`DELETE FROM tokens WHERE user_id=?`, req.OldUserID); err != nil {
		return 0, err
	}

	if err := s.pbClient.MigrateUserID(ctx, req.OldUserID, req.NewUserID); err != nil {
		log.Printf("pocketbase migration warning: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return migratedDevices, nil
}
