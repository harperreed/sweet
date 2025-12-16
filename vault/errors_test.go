// ABOUTME: Tests for typed sync errors.
// ABOUTME: Verifies error wrapping, unwrapping, and Is() matching.
package vault

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	// Verify sentinel errors are distinct
	sentinels := []error{
		ErrTokenExpired,
		ErrUnauthorized,
		ErrNetworkFailure,
		ErrServerError,
		ErrConflict,
		ErrNotConfigured,
		ErrDecryptFailed,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel errors should be distinct: %v matches %v", a, b)
			}
		}
	}
}

func TestSyncError_Error(t *testing.T) {
	err := &SyncError{
		Op:      "push",
		Err:     ErrNetworkFailure,
		Retries: 3,
		Detail:  "connection refused",
	}

	got := err.Error()
	want := "push failed after 3 attempts: network failure"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestSyncError_Unwrap(t *testing.T) {
	err := &SyncError{
		Op:  "pull",
		Err: ErrTokenExpired,
	}

	if !errors.Is(err, ErrTokenExpired) {
		t.Error("errors.Is should match wrapped ErrTokenExpired")
	}

	if errors.Is(err, ErrNetworkFailure) {
		t.Error("errors.Is should not match ErrNetworkFailure")
	}
}

func TestSyncError_WithDetail(t *testing.T) {
	err := &SyncError{
		Op:     "refresh",
		Err:    ErrUnauthorized,
		Detail: "invalid refresh token",
	}

	// Should be able to check both type and underlying error
	var syncErr *SyncError
	if !errors.As(err, &syncErr) {
		t.Error("errors.As should match *SyncError")
	}

	if syncErr.Detail != "invalid refresh token" {
		t.Errorf("Detail = %q, want %q", syncErr.Detail, "invalid refresh token")
	}
}

func TestDecryptError_Error(t *testing.T) {
	err := &DecryptError{
		ChangeID: "change-123",
		Entity:   "passwords",
		UserID:   "user-abc",
		DeviceID: "device-xyz",
		Cause:    errors.New("message authentication failed"),
	}

	got := err.Error()
	// Should include context about the failing change
	if got == "" {
		t.Error("Error() should return non-empty string")
	}

	// Verify the message includes key fields for debugging
	wantSubstrings := []string{"change-123", "passwords", "AAD mismatch"}
	for _, sub := range wantSubstrings {
		if !containsString(got, sub) {
			t.Errorf("Error() = %q, should contain %q", got, sub)
		}
	}
}

func TestDecryptError_Is(t *testing.T) {
	err := &DecryptError{
		ChangeID: "change-123",
		Entity:   "passwords",
		Cause:    errors.New("message authentication failed"),
	}

	if !errors.Is(err, ErrDecryptFailed) {
		t.Error("errors.Is should match ErrDecryptFailed")
	}

	if errors.Is(err, ErrNetworkFailure) {
		t.Error("errors.Is should not match ErrNetworkFailure")
	}
}

func TestDecryptError_As(t *testing.T) {
	err := &DecryptError{
		ChangeID: "change-123",
		Entity:   "passwords",
		UserID:   "user-abc",
		DeviceID: "device-xyz",
		Cause:    errors.New("message authentication failed"),
	}

	var decErr *DecryptError
	if !errors.As(err, &decErr) {
		t.Error("errors.As should match *DecryptError")
	}

	if decErr.ChangeID != "change-123" {
		t.Errorf("ChangeID = %q, want %q", decErr.ChangeID, "change-123")
	}
	if decErr.Entity != "passwords" {
		t.Errorf("Entity = %q, want %q", decErr.Entity, "passwords")
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || containsString(s[1:], substr)))
}
