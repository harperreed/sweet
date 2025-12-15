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
