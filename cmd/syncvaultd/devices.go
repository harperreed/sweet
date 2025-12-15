// ABOUTME: Device management endpoints for listing and revoking devices.
// ABOUTME: Supports multi-device authentication model.

package main

import (
	"log"
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

	devicesCol, err := s.app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	records, err := s.app.FindRecordsByFilter(devicesCol, "user_id = {:user_id}", "", 100, 0,
		map[string]any{"user_id": userID})
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	devices := make([]deviceInfo, 0, len(records))
	for _, r := range records {
		d := deviceInfo{
			DeviceID:    r.GetString("device_id"),
			Name:        r.GetString("name"),
			CreatedAt:   r.GetDateTime("created").Time().Unix(),
			Fingerprint: r.GetString("ssh_pubkey_fp"),
		}
		if lastUsed := r.GetInt("last_used_at"); lastUsed > 0 {
			lu := int64(lastUsed)
			d.LastUsedAt = &lu
		}
		devices = append(devices, d)
	}

	ok(w, map[string]any{"devices": devices})
}

//nolint:funlen // Device revocation requires multiple validation steps.
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
	devicesCol, err := s.app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	deviceRecord, err := s.app.FindFirstRecordByFilter(devicesCol, "device_id = {:device_id}",
		map[string]any{"device_id": deviceID})
	if err != nil {
		fail(w, http.StatusNotFound, "device not found")
		return
	}
	if deviceRecord.GetString("user_id") != userID {
		fail(w, http.StatusForbidden, "not your device")
		return
	}

	// Delete device's tokens first
	tokensCol, err := s.app.FindCollectionByNameOrId("sync_tokens")
	if err != nil {
		log.Printf("find tokens collection error: %v", err)
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	tokens, err := s.app.FindRecordsByFilter(tokensCol, "device_id = {:device_id}", "", 1000, 0,
		map[string]any{"device_id": deviceID})
	if err != nil {
		log.Printf("query tokens error: %v", err)
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	for _, t := range tokens {
		if err := s.app.Delete(t); err != nil {
			log.Printf("delete token error: %v", err)
			fail(w, http.StatusInternalServerError, "failed to revoke token")
			return
		}
	}

	// Delete device
	if err := s.app.Delete(deviceRecord); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, map[string]any{"ok": true, "revoked": deviceID})
}
