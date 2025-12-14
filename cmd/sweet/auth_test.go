// ABOUTME: auth_test.go tests login, logout, and status commands.
// ABOUTME: Uses test server to verify complete authentication flow.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"suitesync/vault"
)

func TestCmdLogin(t *testing.T) {
	keyPath, srv, phrase := setupLoginTest(t)
	defer srv.Close()

	// Test login
	args := []string{"--server", srv.URL, "--ssh-key", keyPath}
	if err := cmdLogin(args); err != nil {
		t.Fatalf("cmdLogin failed: %v", err)
	}

	// Verify results
	verifyLoginSuccess(t, srv, phrase)
}

func setupLoginTest(t *testing.T) (string, *testAuthServer, string) {
	t.Helper()

	// Create temporary SSH key
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_test")
	if err := generateTestSSHKey(keyPath); err != nil {
		t.Fatalf("generate test key: %v", err)
	}

	// Create test server
	srv := newTestAuthServer(t)

	// Setup config
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	t.Cleanup(func() { ConfigPath = originalConfigPath })

	// Initialize config with seed
	_, phrase, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("generate seed: %v", err)
	}
	cfg := &Config{
		Seed:     phrase,
		Server:   "",
		Token:    "",
		DeviceID: "test-device",
		AppDB:    filepath.Join(configDir, "app.db"),
		VaultDB:  filepath.Join(configDir, "vault.db"),
	}
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save initial config: %v", err)
	}

	return keyPath, srv, phrase
}

func verifyLoginSuccess(t *testing.T, srv *testAuthServer, phrase string) {
	t.Helper()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config after login: %v", err)
	}
	if cfg.Token == "" {
		t.Error("expected token to be saved")
	}
	if cfg.TokenExpires == "" {
		t.Error("expected token_expires to be saved")
	}
	if cfg.Server != srv.URL {
		t.Errorf("expected server=%s, got %s", srv.URL, cfg.Server)
	}

	// Verify token expiry is valid timestamp
	_, err = time.Parse(time.RFC3339, cfg.TokenExpires)
	if err != nil {
		t.Errorf("invalid token_expires format: %v", err)
	}

	// Verify user ID
	verifyUserID(t, srv, phrase)
}

func verifyUserID(t *testing.T, srv *testAuthServer, phrase string) {
	t.Helper()

	seedBytes, err := vault.ParseSeedPhrase(phrase)
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	keys, err := vault.DeriveKeys(seedBytes, "", vault.DefaultKDFParams())
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	expectedUserID := keys.UserID()
	if !strings.Contains(srv.lastUserID, expectedUserID[:8]) {
		t.Errorf("expected user_id to contain %s, got %s", expectedUserID[:8], srv.lastUserID)
	}
}

func TestCmdLogout(t *testing.T) {
	// Create test config directory
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	defer func() { ConfigPath = originalConfigPath }()

	// Create config with token
	cfg := &Config{
		Seed:         "test-seed-phrase",
		Server:       "https://example.com",
		Token:        "test-token-12345",
		TokenExpires: time.Now().Add(12 * time.Hour).Format(time.RFC3339),
		DeviceID:     "test-device",
		AppDB:        filepath.Join(configDir, "app.db"),
		VaultDB:      filepath.Join(configDir, "vault.db"),
	}
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	// Test logout
	if err := cmdLogout([]string{}); err != nil {
		t.Fatalf("cmdLogout failed: %v", err)
	}

	// Verify token was cleared
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config after logout: %v", err)
	}
	if cfg.Token != "" {
		t.Errorf("expected token to be cleared, got %s", cfg.Token)
	}
	if cfg.TokenExpires != "" {
		t.Errorf("expected token_expires to be cleared, got %s", cfg.TokenExpires)
	}
	// Other fields should remain
	if cfg.Seed != "test-seed-phrase" {
		t.Error("seed should not be cleared")
	}
	if cfg.Server != "https://example.com" {
		t.Error("server should not be cleared")
	}
}

func TestCmdStatus(t *testing.T) {
	configDir := setupStatusTest(t)

	t.Run("no_config", func(t *testing.T) {
		if err := cmdStatus([]string{}); err != nil {
			t.Fatalf("cmdStatus with no config failed: %v", err)
		}
	})

	t.Run("not_initialized", func(t *testing.T) {
		testStatusNotInitialized(t, configDir)
	})

	t.Run("initialized_not_logged_in", func(t *testing.T) {
		testStatusInitialized(t, configDir)
	})

	t.Run("logged_in_valid_token", func(t *testing.T) {
		testStatusValidToken(t)
	})

	t.Run("expired_token", func(t *testing.T) {
		testStatusExpiredToken(t)
	})
}

func setupStatusTest(t *testing.T) string {
	t.Helper()

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	t.Cleanup(func() { ConfigPath = originalConfigPath })

	return configDir
}

func testStatusNotInitialized(t *testing.T, configDir string) {
	t.Helper()

	cfg := &Config{
		Server:   "",
		Token:    "",
		DeviceID: "test-device",
		AppDB:    filepath.Join(configDir, "app.db"),
		VaultDB:  filepath.Join(configDir, "vault.db"),
	}
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if err := cmdStatus([]string{}); err != nil {
		t.Fatalf("cmdStatus with uninitialized config failed: %v", err)
	}
}

func testStatusInitialized(t *testing.T, configDir string) {
	t.Helper()

	_, phrase, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("generate seed: %v", err)
	}
	cfg := &Config{
		Seed:     phrase,
		Server:   "https://example.com",
		Token:    "",
		DeviceID: "test-device",
		AppDB:    filepath.Join(configDir, "app.db"),
		VaultDB:  filepath.Join(configDir, "vault.db"),
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if err := cmdStatus([]string{}); err != nil {
		t.Fatalf("cmdStatus with no login failed: %v", err)
	}
}

func testStatusValidToken(t *testing.T) {
	t.Helper()

	cfg, _ := LoadConfig()
	cfg.Token = "test-token-12345"
	cfg.TokenExpires = time.Now().Add(6 * time.Hour).Format(time.RFC3339)
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if err := cmdStatus([]string{}); err != nil {
		t.Fatalf("cmdStatus with valid token failed: %v", err)
	}
}

func testStatusExpiredToken(t *testing.T) {
	t.Helper()

	cfg, _ := LoadConfig()
	cfg.TokenExpires = time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if err := cmdStatus([]string{}); err != nil {
		t.Fatalf("cmdStatus with expired token failed: %v", err)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m 30s"},
		{3661 * time.Second, "1h 1m 1s"},
		{7200 * time.Second, "2h 0m 0s"},
		{3 * time.Hour, "3h 0m 0s"},
	}

	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %s, want %s", tt.d, got, tt.want)
		}
	}
}

func TestValueOrNone(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "(not set)"},
		{"value", "value"},
		{"https://example.com", "https://example.com"},
	}

	for _, tt := range tests {
		got := valueOrNone(tt.input)
		if got != tt.want {
			t.Errorf("valueOrNone(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// testAuthServer is a mock auth server for testing.
type testAuthServer struct {
	*httptest.Server
	t          *testing.T
	lastUserID string
}

func newTestAuthServer(t *testing.T) *testAuthServer {
	srv := &testAuthServer{t: t}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/register", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID        string `json:"user_id"`
			SSHPubkeyOpen string `json:"ssh_pubkey_openssh"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		srv.lastUserID = req.UserID
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	})

	mux.HandleFunc("/v1/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID string `json:"user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		srv.lastUserID = req.UserID
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"challenge_id":  "test-challenge-id",
			"challenge_b64": "dGVzdC1jaGFsbGVuZ2UtZGF0YQ==", // "test-challenge-data" base64
			"expires_unix":  time.Now().Add(5 * time.Minute).Unix(),
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	})

	mux.HandleFunc("/v1/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID       string `json:"user_id"`
			ChallengeID  string `json:"challenge_id"`
			SignatureB64 string `json:"signature_b64"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		srv.lastUserID = req.UserID
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"token":        "test-token-12345",
			"expires_unix": time.Now().Add(12 * time.Hour).Unix(),
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	})

	srv.Server = httptest.NewServer(mux)
	return srv
}

func generateTestSSHKey(path string) error {
	// Use ssh-keygen command to generate a test key
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh-keygen", "-t", "ed25519", "-f", path, "-N", "")
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// Test login with missing seed.
func TestCmdLoginNoSeed(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	defer func() { ConfigPath = originalConfigPath }()

	cfg := &Config{
		Seed:     "", // No seed
		Server:   "https://example.com",
		DeviceID: "test-device",
		AppDB:    filepath.Join(configDir, "app.db"),
		VaultDB:  filepath.Join(configDir, "vault.db"),
	}
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	err := cmdLogin([]string{"--server", "https://example.com"})
	if err == nil {
		t.Fatal("expected error when no seed present")
	}
	if !strings.Contains(err.Error(), "no seed") {
		t.Errorf("expected 'no seed' error, got: %v", err)
	}
}

// Test login with missing server.
func TestCmdLoginNoServer(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	defer func() { ConfigPath = originalConfigPath }()

	_, phrase, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("generate seed: %v", err)
	}

	cfg := &Config{
		Seed:     phrase,
		Server:   "", // No server
		DeviceID: "test-device",
		AppDB:    filepath.Join(configDir, "app.db"),
		VaultDB:  filepath.Join(configDir, "vault.db"),
	}
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	err = cmdLogin([]string{})
	if err == nil {
		t.Fatal("expected error when no server specified")
	}
	if !strings.Contains(err.Error(), "no server") {
		t.Errorf("expected 'no server' error, got: %v", err)
	}
}

// Test logout when not logged in.
func TestCmdLogoutNotLoggedIn(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	defer func() { ConfigPath = originalConfigPath }()

	cfg := &Config{
		Seed:     "test-seed",
		Server:   "https://example.com",
		Token:    "", // No token
		DeviceID: "test-device",
		AppDB:    filepath.Join(configDir, "app.db"),
		VaultDB:  filepath.Join(configDir, "vault.db"),
	}
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	// Should not error even when not logged in
	if err := cmdLogout([]string{}); err != nil {
		t.Fatalf("cmdLogout failed: %v", err)
	}
}
