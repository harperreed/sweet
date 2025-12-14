// ABOUTME: config.go provides configuration file management for sweet CLI.
// ABOUTME: Supports loading, saving, and auto-initialization with environment variable overrides.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oklog/ulid/v2"

	"suitesync/vault"
)

// Config represents the sweet CLI configuration.
type Config struct {
	Seed     string `json:"seed"`
	Server   string `json:"server"`
	Token    string `json:"token"`
	AppDB    string `json:"app_db"`
	VaultDB  string `json:"vault_db"`
	DeviceID string `json:"device_id"`
}

// ConfigPath returns the path to the sweet config file.
func ConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".sweet", "config.json")
	}
	return filepath.Join(home, ".sweet", "config.json")
}

// EnsureConfigDir creates the config directory if it doesn't exist.
func EnsureConfigDir() error {
	dir := filepath.Dir(ConfigPath())
	return os.MkdirAll(dir, 0o750)
}

// LoadConfig loads config from file and applies environment variable overrides.
// Returns default config if file doesn't exist.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Server:   "",
		Token:    "",
		AppDB:    filepath.Join(filepath.Dir(ConfigPath()), "app.db"),
		VaultDB:  filepath.Join(filepath.Dir(ConfigPath()), "vault.db"),
		DeviceID: "",
	}

	// Try to load from file
	data, err := os.ReadFile(ConfigPath())
	if err == nil {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Apply environment variable overrides
	if seed := os.Getenv("SWEET_SEED"); seed != "" {
		cfg.Seed = seed
	}
	if server := os.Getenv("SWEET_SERVER"); server != "" {
		cfg.Server = server
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

	return cfg, nil
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

// InitConfig creates a new config with generated seed and device ID.
func InitConfig() (*Config, error) {
	_, phrase, err := vault.NewSeedPhrase()
	if err != nil {
		return nil, fmt.Errorf("generate seed: %w", err)
	}

	deviceID := generateDeviceID()

	cfg := &Config{
		Seed:     phrase,
		Server:   "",
		Token:    "",
		AppDB:    filepath.Join(filepath.Dir(ConfigPath()), "app.db"),
		VaultDB:  filepath.Join(filepath.Dir(ConfigPath()), "vault.db"),
		DeviceID: deviceID,
	}

	if err := SaveConfig(cfg); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Generated new seed phrase (SAVE THIS!):\n")
	fmt.Fprintf(os.Stderr, "  %s\n\n", phrase)
	fmt.Fprintf(os.Stderr, "Config created at %s\n", ConfigPath())

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
