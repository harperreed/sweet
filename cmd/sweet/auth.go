// ABOUTME: auth.go implements login, logout, and status commands for sweet CLI.
// ABOUTME: Handles SSH-based authentication with the sync server and token management.
package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"suitesync/vault"
)

// cmdLogin authenticates with the sync server and saves the token.
func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "sync server URL (overrides config)")
	sshKey := fs.String("ssh-key", vault.DefaultSSHKeyPath(), "path to SSH private key")
	keyPass := fs.String("key-passphrase", "", "SSH key passphrase (if encrypted)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load config
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Validate we have a seed
	if cfg.Seed == "" {
		return fmt.Errorf("no seed found - run 'sweet init' first")
	}

	// Use server from flag or config
	serverURL := *server
	if serverURL == "" {
		serverURL = cfg.Server
	}
	if serverURL == "" {
		return fmt.Errorf("no server URL - use --server flag or set in config")
	}

	// Parse seed and derive keys
	seed, err := vault.ParseSeedPhrase(cfg.Seed)
	if err != nil {
		return fmt.Errorf("parse seed: %w", err)
	}
	keys, err := vault.DeriveKeys(seed, "", vault.DefaultKDFParams())
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}

	// Authenticate
	fmt.Printf("Logging in to %s...\n", serverURL)
	fmt.Printf("Using SSH key: %s\n", *sshKey)
	fmt.Printf("User ID: %s\n\n", keys.UserID())

	authClient := vault.NewAuthClient(serverURL)
	ctx := context.Background()
	token, err := authClient.LoginWithKeyFile(ctx, keys.UserID(), *sshKey, []byte(*keyPass), true)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Save token and server to config
	cfg.Server = serverURL
	cfg.Token = token.Token
	cfg.TokenExpires = token.Expires.Format(time.RFC3339)
	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("✓ Authenticated successfully!")
	fmt.Printf("Token expires: %s\n", token.Expires.Format(time.RFC3339))
	fmt.Printf("Token saved to %s\n", ConfigPath())

	return nil
}

// cmdLogout clears the authentication token from config.
func cmdLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Token == "" {
		fmt.Println("Not logged in")
		return nil
	}

	cfg.Token = ""
	cfg.TokenExpires = ""
	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("✓ Logged out successfully")
	fmt.Printf("Token cleared from %s\n", ConfigPath())

	return nil
}

// cmdStatus shows current configuration and authentication status.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Printf("Config path: %s\n", ConfigPath())
	fmt.Printf("Device ID:   %s\n", cfg.DeviceID)
	fmt.Printf("Server:      %s\n", valueOrNone(cfg.Server))
	fmt.Printf("App DB:      %s\n", cfg.AppDB)
	fmt.Printf("Vault DB:    %s\n", cfg.VaultDB)

	// Check if we have a seed
	if cfg.Seed == "" {
		fmt.Println("\nStatus: Not initialized (run 'sweet init')")
		return nil
	}

	// Derive user ID from seed
	seed, err := vault.ParseSeedPhrase(cfg.Seed)
	if err != nil {
		fmt.Printf("\nWarning: Invalid seed in config: %v\n", err)
	} else {
		keys, err := vault.DeriveKeys(seed, "", vault.DefaultKDFParams())
		if err != nil {
			fmt.Printf("\nWarning: Failed to derive keys: %v\n", err)
		} else {
			fmt.Printf("User ID:     %s\n", keys.UserID())
		}
	}

	// Check authentication status
	printTokenStatus(cfg)

	return nil
}

// printTokenStatus prints the current token authentication status.
func printTokenStatus(cfg *Config) {
	if cfg.Token == "" {
		fmt.Println("\nStatus: Not logged in")
		return
	}

	fmt.Println()
	if cfg.TokenExpires == "" {
		fmt.Println("Token:       valid (no expiry info)")
		return
	}

	expires, err := time.Parse(time.RFC3339, cfg.TokenExpires)
	if err != nil {
		fmt.Printf("Token:       valid (invalid expiry format: %v)\n", err)
		return
	}

	now := time.Now()
	if expires.Before(now) {
		fmt.Printf("Token:       EXPIRED (expired %s ago)\n", now.Sub(expires).Round(time.Second))
	} else {
		remaining := expires.Sub(now)
		fmt.Printf("Token:       valid (expires in %s)\n", formatDuration(remaining))
		fmt.Printf("             %s\n", expires.Format(time.RFC3339))
	}
}

// valueOrNone returns the value or "(not set)" if empty.
func valueOrNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
