// ABOUTME: Tests for PocketBase email/password authentication client.
// ABOUTME: Uses httptest mock server to verify register, login, and refresh flows.
package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthClientRegister(t *testing.T) {
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/register" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		if req.Email == "" || req.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "email and password required"})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":      "usr_123",
			"token":        "tok_abc",
			"expires_unix": time.Now().Add(24 * time.Hour).Unix(),
			"mnemonic":     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		})
	}))
	defer server.Close()

	client := NewPBAuthClient(server.URL)
	result, err := client.Register(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if result.UserID != "usr_123" {
		t.Errorf("unexpected user_id: %s", result.UserID)
	}
	if result.Token.Token != "tok_abc" {
		t.Errorf("unexpected token: %s", result.Token.Token)
	}
	if result.Mnemonic == "" {
		t.Error("expected mnemonic in response")
	}
}

func TestAuthClientLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":       "usr_123",
			"token":         "tok_xyz",
			"refresh_token": "ref_abc",
			"expires_unix":  time.Now().Add(24 * time.Hour).Unix(),
		})
	}))
	defer server.Close()

	client := NewPBAuthClient(server.URL)
	result, err := client.Login(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if result.Token.Token != "tok_xyz" {
		t.Errorf("unexpected token: %s", result.Token.Token)
	}
	if result.RefreshToken != "ref_abc" {
		t.Errorf("unexpected refresh token: %s", result.RefreshToken)
	}
}

func TestAuthClientRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/refresh" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":         "tok_new",
			"refresh_token": "ref_new",
			"expires_unix":  time.Now().Add(24 * time.Hour).Unix(),
		})
	}))
	defer server.Close()

	client := NewPBAuthClient(server.URL)
	result, err := client.Refresh(context.Background(), "ref_old")
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if result.Token.Token != "tok_new" {
		t.Errorf("unexpected token: %s", result.Token.Token)
	}
}
