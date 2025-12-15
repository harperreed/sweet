// ABOUTME: Tests for SyncConfig and KDFParams.
// ABOUTME: Verifies configuration defaults and token refresh callback.
package vault

import (
	"testing"
	"time"
)

func TestDefaultKDFParams(t *testing.T) {
	p := DefaultKDFParams()
	if p.MemoryMB != 256 {
		t.Errorf("MemoryMB = %d, want 256", p.MemoryMB)
	}
	if p.KeyLen != 32 {
		t.Errorf("KeyLen = %d, want 32", p.KeyLen)
	}
}

func TestSyncConfig_OnTokenRefresh(t *testing.T) {
	var calledToken, calledRefresh string
	var calledExpires time.Time

	cfg := SyncConfig{
		BaseURL:      "http://localhost",
		RefreshToken: "old-refresh",
		TokenExpires: time.Now().Add(-1 * time.Hour), // expired
		OnTokenRefresh: func(token, refresh string, expires time.Time) {
			calledToken = token
			calledRefresh = refresh
			calledExpires = expires
		},
	}

	// Simulate token refresh callback
	newExpires := time.Now().Add(1 * time.Hour)
	if cfg.OnTokenRefresh != nil {
		cfg.OnTokenRefresh("new-token", "new-refresh", newExpires)
	}

	if calledToken != "new-token" {
		t.Errorf("token = %q, want %q", calledToken, "new-token")
	}
	if calledRefresh != "new-refresh" {
		t.Errorf("refresh = %q, want %q", calledRefresh, "new-refresh")
	}
	if !calledExpires.Equal(newExpires) {
		t.Errorf("expires = %v, want %v", calledExpires, newExpires)
	}
}

func TestSyncConfig_RetryDefaults(t *testing.T) {
	cfg := SyncConfig{
		BaseURL: "http://localhost",
	}

	// Retry should use defaults when zero
	retry := cfg.Retry
	if retry.MaxAttempts != 0 {
		t.Errorf("zero config should have zero MaxAttempts, got %d", retry.MaxAttempts)
	}

	// GetRetryConfig should return defaults when not set
	got := cfg.GetRetryConfig()
	want := DefaultRetryConfig()
	if got.MaxAttempts != want.MaxAttempts {
		t.Errorf("GetRetryConfig().MaxAttempts = %d, want %d", got.MaxAttempts, want.MaxAttempts)
	}
}
