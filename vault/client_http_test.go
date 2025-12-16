// ABOUTME: Tests for HTTP client including health check and token refresh.
// ABOUTME: Uses httptest for mocking server responses.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Health_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":   true,
			"time": time.Now().Unix(),
		})
	}))
	defer server.Close()

	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      server.URL,
		TokenExpires: time.Now().Add(1 * time.Hour),
	})

	status := client.Health(context.Background())

	if !status.OK {
		t.Error("expected OK = true")
	}
	if status.Latency <= 0 {
		t.Error("expected positive latency")
	}
	if !status.TokenValid {
		t.Error("expected TokenValid = true (token not expired)")
	}
}

func TestClient_Health_ServerDown(t *testing.T) {
	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      "http://localhost:59999", // unlikely to be listening
		TokenExpires: time.Now().Add(1 * time.Hour),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	status := client.Health(ctx)

	if status.OK {
		t.Error("expected OK = false when server unreachable")
	}
}

func TestClient_Health_TokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "time": time.Now().Unix()})
	}))
	defer server.Close()

	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      server.URL,
		TokenExpires: time.Now().Add(-1 * time.Hour), // expired
	})

	status := client.Health(context.Background())

	if !status.OK {
		t.Error("server should be OK")
	}
	if status.TokenValid {
		t.Error("expected TokenValid = false (token expired)")
	}
}

func TestClient_EnsureValidToken_NotExpired(t *testing.T) {
	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      "http://localhost",
		TokenExpires: time.Now().Add(1 * time.Hour), // valid for 1 hour
	})

	err := client.EnsureValidToken(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_EnsureValidToken_ExpiredNoRefresh(t *testing.T) {
	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      "http://localhost",
		TokenExpires: time.Now().Add(-1 * time.Hour), // expired
		RefreshToken: "",                             // no refresh token
	})

	err := client.EnsureValidToken(context.Background())
	if err == nil {
		t.Error("expected error when token expired and no refresh token")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestClient_EnsureValidToken_RefreshSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/pb/refresh" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":         "new-access-token",
				"refresh_token": "new-refresh-token",
				"expires_unix":  time.Now().Add(1 * time.Hour).Unix(),
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	var callbackCalled bool
	var callbackToken string

	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      server.URL,
		AuthToken:    "old-token",
		RefreshToken: "old-refresh",
		TokenExpires: time.Now().Add(-1 * time.Minute), // about to expire
		OnTokenRefresh: func(token, refresh string, expires time.Time) {
			callbackCalled = true
			callbackToken = token
		},
	})

	err := client.EnsureValidToken(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !callbackCalled {
		t.Error("expected OnTokenRefresh callback to be called")
	}
	if callbackToken != "new-access-token" {
		t.Errorf("callback token = %q, want %q", callbackToken, "new-access-token")
	}
}

func TestNewClient_EmptyAppID_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic when AppID is empty")
		}
		msg, ok := r.(string)
		if !ok {
			t.Errorf("panic value is not a string: %v", r)
		}
		expected := "vault: AppID is required - generate a UUID and hardcode it"
		if msg != expected {
			t.Errorf("panic message = %q, want %q", msg, expected)
		}
	}()

	NewClient(SyncConfig{
		AppID:    "",
		BaseURL:  "http://localhost",
		DeviceID: "test-device",
	})
}

func TestNewClient_InvalidUUID_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic when AppID is invalid UUID")
		}
		msg, ok := r.(string)
		if !ok {
			t.Errorf("panic value is not a string: %v", r)
		}
		expected := "vault: AppID must be a valid UUID"
		if msg != expected {
			t.Errorf("panic message = %q, want %q", msg, expected)
		}
	}()

	NewClient(SyncConfig{
		AppID:    "not-a-uuid",
		BaseURL:  "http://localhost",
		DeviceID: "test-device",
	})
}

func TestNewClient_ValidUUID_Works(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic with valid UUID: %v", r)
		}
	}()

	client := NewClient(SyncConfig{
		AppID:    "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:  "http://localhost",
		DeviceID: "test-device",
	})

	if client == nil {
		t.Error("expected client to be created")
	}
	if client.cfg.AppID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("AppID = %q, want %q", client.cfg.AppID, "550e8400-e29b-41d4-a716-446655440000")
	}
}

func TestPrefixedEntity_AddsCorrectPrefix(t *testing.T) {
	client := NewClient(SyncConfig{
		AppID:    "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:  "http://localhost",
		DeviceID: "test-device",
	})

	tests := []struct {
		entity string
		want   string
	}{
		{"item", "550e8400-e29b-41d4-a716-446655440000.item"},
		{"user", "550e8400-e29b-41d4-a716-446655440000.user"},
		{"task", "550e8400-e29b-41d4-a716-446655440000.task"},
		{"", "550e8400-e29b-41d4-a716-446655440000."},
	}

	for _, tt := range tests {
		t.Run(tt.entity, func(t *testing.T) {
			got := client.prefixedEntity(tt.entity)
			if got != tt.want {
				t.Errorf("prefixedEntity(%q) = %q, want %q", tt.entity, got, tt.want)
			}
		})
	}
}

func TestStripPrefix_RemovesPrefixCorrectly(t *testing.T) {
	client := NewClient(SyncConfig{
		AppID:    "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:  "http://localhost",
		DeviceID: "test-device",
	})

	tests := []struct {
		name   string
		entity string
		want   string
	}{
		{
			name:   "prefixed entity",
			entity: "550e8400-e29b-41d4-a716-446655440000.item",
			want:   "item",
		},
		{
			name:   "entity without prefix",
			entity: "item",
			want:   "item",
		},
		{
			name:   "different app prefix",
			entity: "other-uuid.item",
			want:   "other-uuid.item",
		},
		{
			name:   "empty entity",
			entity: "",
			want:   "",
		},
		{
			name:   "just prefix with dot",
			entity: "550e8400-e29b-41d4-a716-446655440000.",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.stripPrefix(tt.entity)
			if got != tt.want {
				t.Errorf("stripPrefix(%q) = %q, want %q", tt.entity, got, tt.want)
			}
		})
	}
}

func TestPrefixRoundTrip(t *testing.T) {
	client := NewClient(SyncConfig{
		AppID:    "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:  "http://localhost",
		DeviceID: "test-device",
	})

	entities := []string{"item", "user", "task", "note"}

	for _, entity := range entities {
		t.Run(entity, func(t *testing.T) {
			prefixed := client.prefixedEntity(entity)
			stripped := client.stripPrefix(prefixed)

			if stripped != entity {
				t.Errorf("round trip failed: %q -> %q -> %q", entity, prefixed, stripped)
			}
		})
	}
}
