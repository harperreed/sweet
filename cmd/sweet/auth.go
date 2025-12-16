// ABOUTME: Implements register, login, logout, and status commands for sweet CLI.
// ABOUTME: Handles PocketBase email/password auth with BIP39 seed management.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/harperreed/sweet/vault"

	"golang.org/x/term"
)

const appID = "sweet"

// cmdRegister creates a new account and generates recovery phrase.
//
//nolint:funlen // Registration flow requires many user interaction steps.
func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "https://api.storeusa.org", "sync server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Get email
	fmt.Print("Email: ")
	reader := bufio.NewReader(os.Stdin)
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email required")
	}

	// Get password
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	password := string(passwordBytes)

	fmt.Print("Confirm password: ")
	confirmBytes, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	if password != string(confirmBytes) {
		return fmt.Errorf("passwords do not match")
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	// Load or initialize config to capture device ID for registration
	cfg, _ := LoadConfig()
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.DeviceID == "" {
		cfg.DeviceID = randHex(16)
	}
	deviceID := cfg.DeviceID

	// Register with server
	fmt.Printf("\nRegistering with %s...\n", *server)
	client := vault.NewPBAuthClient(*server)
	result, err := client.Register(context.Background(), email, password, deviceID)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	fmt.Println("\n✓ Account created!")
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("IMPORTANT: Save this recovery phrase in your password manager.")
	fmt.Println("You will need it to set up other devices or apps.")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	fmt.Println(result.Mnemonic)
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Print("\nPress Enter after you've saved this phrase...")
	_, _ = reader.ReadString('\n')

	// Derive key from mnemonic (we only store the derived key, not the mnemonic)
	seed, err := vault.ParseSeedPhrase(result.Mnemonic)
	if err != nil {
		return fmt.Errorf("parse mnemonic: %w", err)
	}
	derivedKeyHex := hex.EncodeToString(seed.Raw)

	// Save config
	cfg.Server = *server
	cfg.Email = email
	cfg.UserID = result.UserID
	cfg.Token = result.Token.Token
	cfg.TokenExpires = result.Token.Expires.Format(time.RFC3339)
	cfg.DerivedKey = derivedKeyHex
	cfg.AppID = appID
	cfg.DeviceID = deviceID
	if cfg.AppDB == "" {
		cfg.AppDB = ConfigDir() + "/app.db"
	}
	if cfg.VaultDB == "" {
		cfg.VaultDB = ConfigDir() + "/vault.db"
	}

	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("\n✓ Logged in to sweet")
	fmt.Printf("Token expires: %s\n", result.Token.Expires.Format(time.RFC3339))
	fmt.Println("\nPlease check your email to verify your account.")

	return nil
}

// cmdLogin authenticates with email/password and mnemonic.
//
//nolint:funlen // Login flow requires many user interaction steps.
func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "sync server URL (overrides config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, _ := LoadConfig()
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.DeviceID == "" {
		cfg.DeviceID = randHex(16)
	}
	deviceID := cfg.DeviceID

	serverURL := *server
	if serverURL == "" {
		serverURL = cfg.Server
	}
	if serverURL == "" {
		serverURL = "https://api.storeusa.org"
	}

	// Get email
	fmt.Print("Email: ")
	reader := bufio.NewReader(os.Stdin)
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email required")
	}

	// Get password
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	password := string(passwordBytes)

	// Get mnemonic
	fmt.Print("\nEnter your recovery phrase (from your password manager):\n> ")
	mnemonic, _ := reader.ReadString('\n')
	mnemonic = strings.TrimSpace(mnemonic)

	// Validate mnemonic
	if _, err := vault.ParseMnemonic(mnemonic); err != nil {
		return fmt.Errorf("invalid recovery phrase: %w", err)
	}

	// Login to server
	fmt.Printf("\nLogging in to %s...\n", serverURL)
	client := vault.NewPBAuthClient(serverURL)
	result, err := client.Login(context.Background(), email, password, deviceID)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Derive key from mnemonic (we only store the derived key, not the mnemonic)
	seed, err := vault.ParseSeedPhrase(mnemonic)
	if err != nil {
		return fmt.Errorf("parse mnemonic: %w", err)
	}
	derivedKeyHex := hex.EncodeToString(seed.Raw)

	// Save config
	cfg.Server = serverURL
	cfg.Email = email
	cfg.UserID = result.UserID
	cfg.Token = result.Token.Token
	cfg.RefreshToken = result.RefreshToken
	cfg.TokenExpires = result.Token.Expires.Format(time.RFC3339)
	cfg.DerivedKey = derivedKeyHex
	cfg.AppID = appID
	cfg.DeviceID = deviceID
	if cfg.AppDB == "" {
		cfg.AppDB = ConfigDir() + "/app.db"
	}
	if cfg.VaultDB == "" {
		cfg.VaultDB = ConfigDir() + "/vault.db"
	}

	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("\n✓ Logged in to sweet")
	fmt.Printf("Token expires: %s\n", result.Token.Expires.Format(time.RFC3339))

	return nil
}

// cmdLogout clears auth tokens from config.
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
	cfg.RefreshToken = ""
	cfg.TokenExpires = ""
	// Keep mnemonic - user may want to login again

	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("✓ Logged out successfully")
	return nil
}

// cmdStatus shows current auth status.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Printf("Config:    %s\n", ConfigPath())
	fmt.Printf("Server:    %s\n", valueOrNone(cfg.Server))
	fmt.Printf("Email:     %s\n", valueOrNone(cfg.Email))
	fmt.Printf("App ID:    %s\n", valueOrNone(cfg.AppID))
	fmt.Printf("Device ID: %s\n", valueOrNone(cfg.DeviceID))

	if cfg.DerivedKey != "" {
		fmt.Println("Keys:      ✓ configured")
	} else {
		fmt.Println("Keys:      (not set)")
	}

	printTokenStatus(cfg)

	return nil
}

func printTokenStatus(cfg *Config) {
	if cfg.Token == "" {
		fmt.Println("\nStatus: Not logged in")
		return
	}

	fmt.Println()
	if cfg.TokenExpires == "" {
		fmt.Println("Token: valid (no expiry info)")
		return
	}

	expires, err := time.Parse(time.RFC3339, cfg.TokenExpires)
	if err != nil {
		fmt.Printf("Token: valid (invalid expiry: %v)\n", err)
		return
	}

	now := time.Now()
	if expires.Before(now) {
		fmt.Printf("Token: EXPIRED (%s ago)\n", now.Sub(expires).Round(time.Second))
		if cfg.RefreshToken != "" {
			fmt.Println("       (has refresh token - run any command to auto-refresh)")
		}
	} else {
		fmt.Printf("Token: valid (expires in %s)\n", formatDuration(expires.Sub(now)))
	}
}

func valueOrNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// cmdWhoami shows current account identity.
func cmdWhoami(args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Email == "" {
		fmt.Println("Not logged in")
		return nil
	}

	fmt.Println(cfg.Email)

	// Show derived user ID if derived key is available
	if cfg.DerivedKey != "" {
		seed, err := vault.ParseSeedPhrase(cfg.DerivedKey)
		if err == nil {
			keys, err := vault.DeriveKeys(seed, "", vault.DefaultKDFParams())
			if err == nil {
				fmt.Printf("vault:%s\n", keys.UserID())
			}
		}
	}

	return nil
}

// randHex returns n random bytes hex-encoded (2n chars).
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
