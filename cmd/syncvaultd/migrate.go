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

	"github.com/pocketbase/pocketbase/core"
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
	// Create new user record if it doesn't exist
	usersCol, err := s.app.FindCollectionByNameOrId("sync_users")
	if err != nil {
		return 0, err
	}

	_, err = s.app.FindFirstRecordByFilter(usersCol, "user_id = {:user_id}",
		map[string]any{"user_id": req.NewUserID})
	if err != nil {
		// User doesn't exist, create it
		userRecord := core.NewRecord(usersCol)
		userRecord.Set("user_id", req.NewUserID)
		if err := s.app.Save(userRecord); err != nil {
			return 0, err
		}
	}

	// Update devices to point to new user
	devicesCol, err := s.app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		return 0, err
	}

	devices, err := s.app.FindRecordsByFilter(devicesCol, "user_id = {:user_id}", "", 1000, 0,
		map[string]any{"user_id": req.OldUserID})
	if err != nil {
		return 0, err
	}

	var migratedDevices int64
	for _, d := range devices {
		d.Set("user_id", req.NewUserID)
		if err := s.app.Save(d); err != nil {
			log.Printf("migrate device error: %v", err)
			continue
		}
		migratedDevices++
	}

	// sync_tokens collection removed - JWT auth uses PocketBase tokens now

	// Call external PocketBase migration if client exists
	if s.pbClient != nil {
		if err := s.pbClient.MigrateUserID(ctx, req.OldUserID, req.NewUserID); err != nil {
			log.Printf("pocketbase migration warning: %v", err)
		}
	}

	return migratedDevices, nil
}
