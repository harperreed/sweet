// ABOUTME: Device management endpoints for listing and revoking devices.
// ABOUTME: Supports multi-device authentication model.

package main

import (
	"net/http"
	"strings"
)

type deviceInfo struct {
	DeviceID    string `json:"device_id"`
	Name        string `json:"name,omitempty"`
	CreatedAt   int64  `json:"created_at"`
	LastUsedAt  *int64 `json:"last_used_at,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID := r.Context().Value(ctxUserIDKey{}).(string)

	rows, err := s.db.QueryContext(r.Context(), `
SELECT device_id, name, created_at, last_used_at, ssh_pubkey_fp
FROM devices WHERE user_id = ?
ORDER BY created_at DESC
`, userID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	defer func() {
		_ = rows.Close()
	}()

	devices := []deviceInfo{}
	for rows.Next() {
		var d deviceInfo
		var name *string
		var lastUsed *int64
		if err := rows.Scan(&d.DeviceID, &name, &d.CreatedAt, &lastUsed, &d.Fingerprint); err != nil {
			fail(w, http.StatusInternalServerError, "db error")
			return
		}
		if name != nil {
			d.Name = *name
		}
		d.LastUsedAt = lastUsed
		devices = append(devices, d)
	}

	ok(w, map[string]any{"devices": devices})
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID := r.Context().Value(ctxUserIDKey{}).(string)
	currentDeviceID := r.Context().Value(ctxDeviceIDKey{}).(string)

	// Extract device_id from path: /v1/devices/{device_id}
	path := strings.TrimPrefix(r.URL.Path, "/v1/devices/")
	deviceID := strings.TrimSpace(path)
	if deviceID == "" {
		fail(w, http.StatusBadRequest, "device_id required")
		return
	}

	// Prevent self-revocation
	if deviceID == currentDeviceID {
		fail(w, http.StatusForbidden, "cannot revoke current device")
		return
	}

	// Verify device belongs to user
	var owner string
	err := s.db.QueryRowContext(r.Context(), `SELECT user_id FROM devices WHERE device_id=?`, deviceID).Scan(&owner)
	if err != nil {
		fail(w, http.StatusNotFound, "device not found")
		return
	}
	if owner != userID {
		fail(w, http.StatusForbidden, "not your device")
		return
	}

	// Delete device and its tokens
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.Exec(`DELETE FROM tokens WHERE device_id=?`, deviceID); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	if _, err := tx.Exec(`DELETE FROM devices WHERE device_id=?`, deviceID); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	if err := tx.Commit(); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, map[string]any{"ok": true, "revoked": deviceID})
}
