// ABOUTME: Typed errors for vault sync operations.
// ABOUTME: Enables programmatic error handling with errors.Is() and errors.As().
package vault

import (
	"errors"
	"fmt"
)

// Sentinel errors for programmatic handling.
var (
	ErrTokenExpired   = errors.New("token expired")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrNetworkFailure = errors.New("network failure")
	ErrServerError    = errors.New("server error")
	ErrConflict       = errors.New("conflict detected")
	ErrNotConfigured  = errors.New("sync not configured")
	ErrDecryptFailed  = errors.New("decrypt failed")
)

// SyncError wraps errors with operation context.
type SyncError struct {
	Op      string // "push", "pull", "refresh"
	Err     error  // underlying typed error
	Retries int    // attempts made
	Detail  string // server message if any
}

func (e *SyncError) Error() string {
	return fmt.Sprintf("%s failed after %d attempts: %v", e.Op, e.Retries, e.Err)
}

func (e *SyncError) Unwrap() error {
	return e.Err
}

// DecryptError provides context when decryption fails during sync.
// This typically indicates an AAD mismatch (wrong userID, deviceID, or data corruption).
type DecryptError struct {
	ChangeID string // ID of the change that failed
	Entity   string // Entity type (e.g., "passwords", "notes")
	UserID   string // User ID used in AAD
	DeviceID string // Device ID used in AAD
	Cause    error  // Underlying crypto error
}

func (e *DecryptError) Error() string {
	return fmt.Sprintf(
		"decrypt failed for change %s (entity: %s): AAD mismatch - "+
			"check userID/deviceID match encryption context (userID: %s, deviceID: %s): %v",
		e.ChangeID, e.Entity, e.UserID, e.DeviceID, e.Cause,
	)
}

func (e *DecryptError) Unwrap() error {
	return e.Cause
}

func (e *DecryptError) Is(target error) bool {
	return target == ErrDecryptFailed
}
