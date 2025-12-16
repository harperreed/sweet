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
		if r.URL.Path != "/v1/auth/pb/register" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			DeviceID string `json:"device_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		if req.Email == "" || req.Password == "" || req.DeviceID == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "email, password, and device required"})
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
	result, err := client.Register(context.Background(), "test@example.com", "password123", "test-device")
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
		if r.URL.Path != "/v1/auth/pb/login" {
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
	result, err := client.Login(context.Background(), "test@example.com", "password123", "test-device")
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
		if r.URL.Path != "/v1/auth/pb/refresh" {
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

func TestAuthClientRegisterEmptyCredentials(t *testing.T) {
	client := NewPBAuthClient("http://localhost:8080")

	testCases := []struct {
		name     string
		email    string
		password string
	}{
		{
			name:     "empty email",
			email:    "",
			password: "password123",
		},
		{
			name:     "empty password",
			email:    "test@example.com",
			password: "",
		},
		{
			name:     "both empty",
			email:    "",
			password: "",
		},
		{
			name:     "whitespace email",
			email:    "   ",
			password: "password123",
		},
		{
			name:     "whitespace password",
			email:    "test@example.com",
			password: "   ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.Register(context.Background(), tc.email, tc.password, "device-123")
			if err == nil {
				t.Fatal("expected error for empty credentials, got nil")
			}
			if err.Error() != "email and password required" {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

func TestAuthClientRegisterMissingDeviceID(t *testing.T) {
	client := NewPBAuthClient("http://localhost:8080")
	_, err := client.Register(context.Background(), "test@example.com", "password123", "")
	if err == nil || err.Error() != "device id required" {
		t.Fatalf("expected device id required error, got %v", err)
	}
}

func TestAuthClientLoginServerError(t *testing.T) {
	testCases := []struct {
		name           string
		statusCode     int
		responseBody   map[string]string
		expectedErrMsg string
	}{
		{
			name:           "401 unauthorized",
			statusCode:     http.StatusUnauthorized,
			responseBody:   map[string]string{"error": "invalid credentials"},
			expectedErrMsg: "login failed: invalid credentials",
		},
		{
			name:           "409 conflict",
			statusCode:     http.StatusConflict,
			responseBody:   map[string]string{"error": "user already exists"},
			expectedErrMsg: "login failed: user already exists",
		},
		{
			name:           "500 internal server error",
			statusCode:     http.StatusInternalServerError,
			responseBody:   map[string]string{"error": "database error"},
			expectedErrMsg: "login failed: database error",
		},
		{
			name:           "503 service unavailable",
			statusCode:     http.StatusServiceUnavailable,
			responseBody:   map[string]string{},
			expectedErrMsg: "login failed: 503 Service Unavailable",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				if len(tc.responseBody) > 0 {
					_ = json.NewEncoder(w).Encode(tc.responseBody)
				}
			}))
			defer server.Close()

			client := NewPBAuthClient(server.URL)
			_, err := client.Login(context.Background(), "test@example.com", "password123", "device-xyz")
			if err == nil {
				t.Fatal("expected error for server error, got nil")
			}
			if err.Error() != tc.expectedErrMsg {
				t.Errorf("unexpected error message:\ngot:  %v\nwant: %v", err.Error(), tc.expectedErrMsg)
			}
		})
	}
}

func TestAuthClientRefreshInvalidToken(t *testing.T) {
	t.Run("empty token", func(t *testing.T) {
		client := NewPBAuthClient("http://localhost:8080")
		_, err := client.Refresh(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty token, got nil")
		}
		if err.Error() != "refresh token required" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid token format", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid refresh token"})
		}))
		defer server.Close()

		client := NewPBAuthClient(server.URL)
		_, err := client.Refresh(context.Background(), "invalid_token")
		if err == nil || err.Error() != "refresh failed: invalid refresh token" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "refresh token expired"})
		}))
		defer server.Close()

		client := NewPBAuthClient(server.URL)
		_, err := client.Refresh(context.Background(), "expired_token")
		if err == nil || err.Error() != "refresh failed: refresh token expired" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("revoked token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "refresh token revoked"})
		}))
		defer server.Close()

		client := NewPBAuthClient(server.URL)
		_, err := client.Refresh(context.Background(), "revoked_token")
		if err == nil || err.Error() != "refresh failed: refresh token revoked" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
