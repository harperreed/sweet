// ABOUTME: auth_test.go tests authentication helper functions.
// ABOUTME: Full auth flow testing requires integration tests (see Task 7).
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCmdLogout tests the logout command clears tokens properly.
func TestCmdLogout(t *testing.T) {
	// Create test config directory
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	defer func() { ConfigPath = originalConfigPath }()

	// Create config with token
	cfg := &Config{
		Email:        "test@example.com",
		Mnemonic:     "test mnemonic phrase",
		Server:       "https://example.com",
		Token:        "test-token-12345",
		RefreshToken: "test-refresh-token",
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

	// Verify tokens were cleared
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config after logout: %v", err)
	}
	if cfg.Token != "" {
		t.Errorf("expected token to be cleared, got %s", cfg.Token)
	}
	if cfg.RefreshToken != "" {
		t.Errorf("expected refresh_token to be cleared, got %s", cfg.RefreshToken)
	}
	if cfg.TokenExpires != "" {
		t.Errorf("expected token_expires to be cleared, got %s", cfg.TokenExpires)
	}
	// Other fields should remain
	if cfg.Mnemonic != "test mnemonic phrase" {
		t.Error("mnemonic should not be cleared")
	}
	if cfg.Email != "test@example.com" {
		t.Error("email should not be cleared")
	}
	if cfg.Server != "https://example.com" {
		t.Error("server should not be cleared")
	}
}

// TestCmdStatus tests status command doesn't error in various states.
//
//nolint:funlen // Table-driven test with multiple sub-tests requires setup code.
func TestCmdStatus(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	t.Cleanup(func() { ConfigPath = originalConfigPath })

	t.Run("no_config", func(t *testing.T) {
		if err := cmdStatus([]string{}); err != nil {
			t.Fatalf("cmdStatus with no config failed: %v", err)
		}
	})

	t.Run("not_initialized", func(t *testing.T) {
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
	})

	t.Run("initialized_not_logged_in", func(t *testing.T) {
		cfg := &Config{
			Email:    "test@example.com",
			Mnemonic: "test mnemonic phrase words",
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
	})

	t.Run("logged_in_valid_token", func(t *testing.T) {
		cfg, _ := LoadConfig()
		cfg.Token = "test-token-12345"
		cfg.TokenExpires = time.Now().Add(6 * time.Hour).Format(time.RFC3339)
		if err := SaveConfig(cfg); err != nil {
			t.Fatalf("save config: %v", err)
		}
		if err := cmdStatus([]string{}); err != nil {
			t.Fatalf("cmdStatus with valid token failed: %v", err)
		}
	})

	t.Run("expired_token", func(t *testing.T) {
		cfg, _ := LoadConfig()
		cfg.TokenExpires = time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
		if err := SaveConfig(cfg); err != nil {
			t.Fatalf("save config: %v", err)
		}
		if err := cmdStatus([]string{}); err != nil {
			t.Fatalf("cmdStatus with expired token failed: %v", err)
		}
	})
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m 30s"},
		{3661 * time.Second, "1h 1m"},
		{7200 * time.Second, "2h 0m"},
		{3 * time.Hour, "3h 0m"},
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

// TestCmdLogoutNotLoggedIn tests logout when not logged in.
func TestCmdLogoutNotLoggedIn(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	originalConfigPath := ConfigPath
	ConfigPath = func() string { return configPath }
	defer func() { ConfigPath = originalConfigPath }()

	cfg := &Config{
		Mnemonic: "test mnemonic",
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
