// ABOUTME: config.go provides configuration file management for sweet CLI.
// ABOUTME: Supports loading, saving, and auto-initialization with environment variable overrides.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Config represents the sweet CLI configuration.
type Config struct {
	Server       string `json:"server"`
	Email        string `json:"email"`
	UserID       string `json:"user_id"` // PocketBase record ID from login
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	TokenExpires string `json:"token_expires,omitempty"`
	DerivedKey   string `json:"derived_key"` // Hex-encoded 32-byte key derived from mnemonic
	AppID        string `json:"app_id"`
	DeviceID     string `json:"device_id"`
	AppDB        string `json:"app_db"`
	VaultDB      string `json:"vault_db"`
}

// ConfigPath is a function that returns the path to the sweet config file.
// It can be overridden in tests.
var ConfigPath = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".sweet", "config.json")
	}
	return filepath.Join(home, ".sweet", "config.json")
}

// ConfigDir returns the directory containing the config file.
func ConfigDir() string {
	return filepath.Dir(ConfigPath())
}

// EnsureConfigDir creates the config directory if it doesn't exist.
// Handles edge cases like the path being a file instead of a directory.
//
//nolint:nestif // Complex nested blocks needed to handle various filesystem states.
func EnsureConfigDir() error {
	dir := ConfigDir()

	// Check if path exists
	info, err := os.Stat(dir)
	if err == nil {
		// Path exists - make sure it's a directory
		if !info.IsDir() {
			// It's a file, back it up and create directory
			backup := dir + ".backup." + time.Now().Format("20060102-150405")
			if err := os.Rename(dir, backup); err != nil {
				return fmt.Errorf("config path %s is a file, failed to backup: %w", dir, err)
			}
			fmt.Fprintf(os.Stderr, "Warning: %s was a file, backed up to %s\n", dir, backup)
		} else {
			return nil // Already a directory
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check config dir: %w", err)
	}

	return os.MkdirAll(dir, 0o750)
}

// LoadConfig loads config from file and applies environment variable overrides.
// Returns default config if file doesn't exist or is corrupted.
func LoadConfig() (*Config, error) {
	cfg := defaultConfig()

	configPath := ConfigPath()

	// Check if config path is a directory (user error)
	info, statErr := os.Stat(configPath)
	if statErr == nil && info.IsDir() {
		return nil, fmt.Errorf("config path %s is a directory, not a file\nRun 'sweet reset' to fix this", configPath)
	}

	// Try to load from file
	// #nosec G304 -- configPath is derived from user's home directory, not user input
	data, err := os.ReadFile(configPath)
	if err == nil {
		if jsonErr := json.Unmarshal(data, cfg); jsonErr != nil {
			// Config file is corrupted - back it up and return error with helpful message
			backup := configPath + ".corrupt." + time.Now().Format("20060102-150405")
			if renameErr := os.Rename(configPath, backup); renameErr == nil {
				fmt.Fprintf(os.Stderr, "Warning: corrupted config backed up to %s\n", backup)
			}
			return nil, fmt.Errorf("config file corrupted: %w\nRun 'sweet init' to create a new config", jsonErr)
		}
	} else if !os.IsNotExist(err) {
		// Some other error (permissions, etc)
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Apply environment variable overrides
	applyEnvOverrides(cfg)

	// Ensure paths are set to defaults if empty
	if cfg.AppDB == "" {
		cfg.AppDB = filepath.Join(ConfigDir(), "app.db")
	}
	if cfg.VaultDB == "" {
		cfg.VaultDB = filepath.Join(ConfigDir(), "vault.db")
	}

	return cfg, nil
}

// defaultConfig returns a config with sensible defaults.
func defaultConfig() *Config {
	return &Config{
		Server:   "",
		Token:    "",
		AppDB:    filepath.Join(ConfigDir(), "app.db"),
		VaultDB:  filepath.Join(ConfigDir(), "vault.db"),
		DeviceID: "",
	}
}

// applyEnvOverrides applies environment variable overrides to config.
func applyEnvOverrides(cfg *Config) {
	if server := os.Getenv("SWEET_SERVER"); server != "" {
		cfg.Server = server
	}
	if email := os.Getenv("SWEET_EMAIL"); email != "" {
		cfg.Email = email
	}
	if token := os.Getenv("SWEET_TOKEN"); token != "" {
		cfg.Token = token
	}
	if appDB := os.Getenv("SWEET_APP_DB"); appDB != "" {
		cfg.AppDB = expandPath(appDB)
	}
	if vaultDB := os.Getenv("SWEET_VAULT_DB"); vaultDB != "" {
		cfg.VaultDB = expandPath(vaultDB)
	}
	if deviceID := os.Getenv("SWEET_DEVICE_ID"); deviceID != "" {
		cfg.DeviceID = deviceID
	}
}

// SaveConfig writes config to file.
func SaveConfig(cfg *Config) error {
	if err := EnsureConfigDir(); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(ConfigPath(), data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// InitConfig creates a new config with device ID but no seed (use register/login for auth).
func InitConfig() (*Config, error) {
	deviceID := generateDeviceID()

	cfg := &Config{
		Server:   "",
		Email:    "",
		Token:    "",
		AppID:    "sweet",
		DeviceID: deviceID,
		AppDB:    filepath.Join(filepath.Dir(ConfigPath()), "app.db"),
		VaultDB:  filepath.Join(filepath.Dir(ConfigPath()), "vault.db"),
	}

	if err := SaveConfig(cfg); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Config created at %s\n", ConfigPath())
	fmt.Fprintf(os.Stderr, "Device ID: %s\n", deviceID)
	fmt.Fprintf(os.Stderr, "\nNext: Run 'sweet register' to create an account\n")

	return cfg, nil
}

// ConfigExists returns true if config file exists.
func ConfigExists() bool {
	_, err := os.Stat(ConfigPath())
	return err == nil
}

// generateDeviceID creates a unique device identifier.
func generateDeviceID() string {
	return ulid.Make().String()
}

// expandPath expands ~ to home directory.
func expandPath(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
