package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"suitesync/vault"
)

func TestConfigPath(t *testing.T) {
	path := ConfigPath()
	if path == "" {
		t.Fatal("ConfigPath returned empty string")
	}
	if !filepath.IsAbs(path) {
		t.Errorf("ConfigPath returned relative path: %s", path)
	}
}

func TestEnsureConfigDir(t *testing.T) {
	// Use temp directory for testing
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	if err := EnsureConfigDir(); err != nil {
		t.Fatalf("EnsureConfigDir failed: %v", err)
	}

	dir := filepath.Dir(ConfigPath())
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("Config directory not created: %s", dir)
	}
}

func TestLoadConfig_NotExists(t *testing.T) {
	// Use temp directory for testing
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed when file doesn't exist: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil config")
	}

	// Should have default values
	if cfg.AppDB == "" {
		t.Error("Default AppDB not set")
	}
	if cfg.VaultDB == "" {
		t.Error("Default VaultDB not set")
	}
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	// Use temp directory for testing
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	// Set environment variables
	testSeed := "abc123"
	testServer := "https://example.com"
	testToken := "test-token"
	testDeviceID := "test-device"

	_ = os.Setenv("SWEET_SEED", testSeed)
	_ = os.Setenv("SWEET_SERVER", testServer)
	_ = os.Setenv("SWEET_TOKEN", testToken)
	_ = os.Setenv("SWEET_DEVICE_ID", testDeviceID)
	defer func() {
		_ = os.Unsetenv("SWEET_SEED")
		_ = os.Unsetenv("SWEET_SERVER")
		_ = os.Unsetenv("SWEET_TOKEN")
		_ = os.Unsetenv("SWEET_DEVICE_ID")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Seed != testSeed {
		t.Errorf("Seed not set from env: got %s, want %s", cfg.Seed, testSeed)
	}
	if cfg.Server != testServer {
		t.Errorf("Server not set from env: got %s, want %s", cfg.Server, testServer)
	}
	if cfg.Token != testToken {
		t.Errorf("Token not set from env: got %s, want %s", cfg.Token, testToken)
	}
	if cfg.DeviceID != testDeviceID {
		t.Errorf("DeviceID not set from env: got %s, want %s", cfg.DeviceID, testDeviceID)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	// Use temp directory for testing
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	// Create a config
	originalCfg := &Config{
		Seed:     "test-seed-phrase",
		Server:   "https://test.example.com",
		Token:    "test-token",
		AppDB:    filepath.Join(tmpDir, "app.db"),
		VaultDB:  filepath.Join(tmpDir, "vault.db"),
		DeviceID: "test-device-123",
	}

	// Save it
	if err := SaveConfig(originalCfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Load it back
	loadedCfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Compare
	if loadedCfg.Seed != originalCfg.Seed {
		t.Errorf("Seed mismatch: got %s, want %s", loadedCfg.Seed, originalCfg.Seed)
	}
	if loadedCfg.Server != originalCfg.Server {
		t.Errorf("Server mismatch: got %s, want %s", loadedCfg.Server, originalCfg.Server)
	}
	if loadedCfg.Token != originalCfg.Token {
		t.Errorf("Token mismatch: got %s, want %s", loadedCfg.Token, originalCfg.Token)
	}
	if loadedCfg.AppDB != originalCfg.AppDB {
		t.Errorf("AppDB mismatch: got %s, want %s", loadedCfg.AppDB, originalCfg.AppDB)
	}
	if loadedCfg.VaultDB != originalCfg.VaultDB {
		t.Errorf("VaultDB mismatch: got %s, want %s", loadedCfg.VaultDB, originalCfg.VaultDB)
	}
	if loadedCfg.DeviceID != originalCfg.DeviceID {
		t.Errorf("DeviceID mismatch: got %s, want %s", loadedCfg.DeviceID, originalCfg.DeviceID)
	}
}

func TestInitConfig(t *testing.T) {
	// Use temp directory for testing
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	// Capture stderr
	oldStderr := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w
	defer func() {
		os.Stderr = oldStderr
	}()

	cfg, err := InitConfig()
	if err != nil {
		t.Fatalf("InitConfig failed: %v", err)
	}

	_ = w.Close()
	os.Stderr = oldStderr

	// Verify config was created
	if cfg.Seed == "" {
		t.Error("Seed not generated")
	}
	if cfg.DeviceID == "" {
		t.Error("DeviceID not generated")
	}
	if cfg.AppDB == "" {
		t.Error("AppDB not set")
	}
	if cfg.VaultDB == "" {
		t.Error("VaultDB not set")
	}

	// Verify seed is valid hex
	seedBytes, err := hex.DecodeString(cfg.Seed)
	if err != nil {
		t.Errorf("Seed is not valid hex: %v", err)
	}

	// Verify we can parse it as a seed phrase
	_, err = vault.ParseSeedPhrase(cfg.Seed)
	if err != nil {
		t.Errorf("Generated seed is not a valid seed phrase: %v", err)
	}

	// Verify seed has correct length (32 bytes = 64 hex chars)
	if len(seedBytes) != 32 {
		t.Errorf("Seed has wrong length: got %d bytes, want 32", len(seedBytes))
	}

	// Verify config file exists
	if !ConfigExists() {
		t.Error("Config file not created")
	}

	// Load and verify
	loadedCfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loadedCfg.Seed != cfg.Seed {
		t.Error("Loaded config seed doesn't match")
	}
}

func TestConfigExists(t *testing.T) {
	// Use temp directory for testing
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	// Should not exist initially
	if ConfigExists() {
		t.Error("ConfigExists returned true for non-existent config")
	}

	// Create config
	if err := EnsureConfigDir(); err != nil {
		t.Fatalf("EnsureConfigDir failed: %v", err)
	}
	cfg := &Config{
		Seed: "test",
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Should exist now
	if !ConfigExists() {
		t.Error("ConfigExists returned false for existing config")
	}
}

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHome bool
	}{
		{"absolute path", "/tmp/test.db", false},
		{"relative path", "test.db", false},
		{"tilde path", "~/.sweet/test.db", true},
		{"tilde only", "~/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPath(tt.input)
			if tt.wantHome {
				home, _ := os.UserHomeDir()
				if home != "" && result == tt.input {
					t.Errorf("expandPath(%q) = %q, expected tilde to be expanded", tt.input, result)
				}
			} else if result != tt.input {
				t.Errorf("expandPath(%q) = %q, expected no change", tt.input, result)
			}
		})
	}
}
