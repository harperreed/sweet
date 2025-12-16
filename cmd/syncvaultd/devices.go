// ABOUTME: Device management endpoints for listing and revoking devices.
// ABOUTME: Supports multi-device authentication model.

package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

type deviceInfo struct {
	DeviceID   string `json:"device_id"`
	Name       string `json:"name,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt *int64 `json:"last_used_at,omitempty"`
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
			DeviceID:  r.GetString("device_id"),
			Name:      r.GetString("name"),
			CreatedAt: r.GetDateTime("created").Time().Unix(),
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

	if err := s.recordDeviceRevocation(userID, deviceID); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.Delete(deviceRecord); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, map[string]any{"ok": true, "revoked": deviceID})
}

// ensureDeviceAllowed verifies the device exists and updates last_used_at.
func (s *Server) ensureDeviceAllowed(userID, deviceID string) error {
	devicesCol, err := s.app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		return errors.New("devices collection not found")
	}

	record, err := s.app.FindFirstRecordByFilter(devicesCol, "device_id = {:device_id}",
		map[string]any{"device_id": deviceID})
	if err != nil {
		return errors.New("device not registered")
	}
	if record.GetString("user_id") != userID {
		return errors.New("device not registered for this user")
	}

	record.Set("last_used_at", time.Now().Unix())
	if err := s.app.Save(record); err != nil {
		return errors.New("failed to update device usage")
	}
	return nil
}

// registerDevice records device metadata after register/login.
func (s *Server) registerDevice(userID, deviceID string) error {
	if deviceID == "" {
		return errors.New("device id required")
	}

	if revoked, err := s.isDeviceRevoked(userID, deviceID); err != nil {
		return err
	} else if revoked {
		return errors.New("device has been revoked")
	}

	devicesCol, err := s.app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		return errors.New("devices collection not found")
	}

	record, err := s.app.FindFirstRecordByFilter(devicesCol, "device_id = {:device_id}",
		map[string]any{"device_id": deviceID})
	if err == nil {
		if record.GetString("user_id") != userID {
			return errors.New("device belongs to another user")
		}
		record.Set("last_used_at", time.Now().Unix())
		return s.app.Save(record)
	}

	newDevice := core.NewRecord(devicesCol)
	newDevice.Set("user_id", userID)
	newDevice.Set("device_id", deviceID)
	newDevice.Set("name", deviceID)
	newDevice.Set("last_used_at", time.Now().Unix())
	return s.app.Save(newDevice)
}

func (s *Server) recordDeviceRevocation(userID, deviceID string) error {
	revokedCol, err := s.app.FindCollectionByNameOrId("revoked_devices")
	if err != nil {
		return errors.New("revoked devices collection not found")
	}

	_, err = s.app.FindFirstRecordByFilter(revokedCol, "user_id = {:user_id} && device_id = {:device_id}",
		map[string]any{"user_id": userID, "device_id": deviceID})
	if err == nil {
		return nil
	}

	record := core.NewRecord(revokedCol)
	record.Set("user_id", userID)
	record.Set("device_id", deviceID)
	record.Set("revoked_at", time.Now().Unix())
	if err := s.app.Save(record); err != nil {
		return errors.New("failed to record revocation")
	}
	return nil
}

func (s *Server) isDeviceRevoked(userID, deviceID string) (bool, error) {
	revokedCol, err := s.app.FindCollectionByNameOrId("revoked_devices")
	if err != nil {
		return false, errors.New("revoked devices collection not found")
	}

	record, err := s.app.FindFirstRecordByFilter(revokedCol, "user_id = {:user_id} && device_id = {:device_id}",
		map[string]any{"user_id": userID, "device_id": deviceID})
	if err != nil {
		return false, nil
	}
	if record.GetString("user_id") != userID {
		return true, nil
	}
	return true, nil
}

// ensureDeviceExists checks that a device belongs to the user without updating metadata.
func (s *Server) ensureDeviceExists(userID, deviceID string) error {
	devicesCol, err := s.app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		return errors.New("devices collection not found")
	}

	record, err := s.app.FindFirstRecordByFilter(devicesCol, "device_id = {:device_id}",
		map[string]any{"device_id": deviceID})
	if err != nil {
		return errors.New("device not registered")
	}
	if record.GetString("user_id") != userID {
		return errors.New("device not registered for this user")
	}
	return nil
}
