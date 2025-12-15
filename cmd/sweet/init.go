// ABOUTME: init.go provides the init and reset commands to create or recreate sweet configuration.
// ABOUTME: Generates new seed phrase and device ID, creates config file.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite existing config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if ConfigExists() && !*force {
		return fmt.Errorf("config already exists at %s (use --force to overwrite)", ConfigPath())
	}

	cfg, err := InitConfig()
	if err != nil {
		return err
	}

	fmt.Printf("Device ID: %s\n", cfg.DeviceID)
	fmt.Println("\nConfiguration initialized successfully!")
	fmt.Println("You can now use 'sweet kv' commands.")

	return nil
}

// cmdReset removes and recreates the entire config directory.
// This is useful when the config is corrupted or in a bad state.
//
//nolint:funlen,nestif // Reset requires multiple cleanup, backup, and user confirmation steps.
func cmdReset(args []string) error {
	fs := flag.NewFlagSet("reset", flag.ExitOnError)
	force := fs.Bool("force", false, "skip confirmation prompt")
	keepSeed := fs.Bool("keep-seed", false, "preserve existing seed phrase if possible")
	if err := fs.Parse(args); err != nil {
		return err
	}

	configDir := ConfigDir()
	configPath := ConfigPath()

	// Try to preserve derived key if requested
	var existingDerivedKey string
	if *keepSeed {
		cfg, err := LoadConfig()
		if err == nil && cfg.DerivedKey != "" {
			existingDerivedKey = cfg.DerivedKey
			fmt.Fprintf(os.Stderr, "Found existing encryption key, will preserve it.\n")
		}
	}

	// Confirm with user unless --force
	if !*force {
		fmt.Printf("This will remove everything in %s and create a fresh config.\n", configDir)
		if existingDerivedKey == "" {
			fmt.Println("WARNING: Your encryption keys will be lost! Make sure you have your recovery phrase backed up.")
		}
		fmt.Print("Continue? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Backup existing directory if it exists
	if info, err := os.Stat(configDir); err == nil {
		backup := configDir + ".backup." + time.Now().Format("20060102-150405")
		if info.IsDir() {
			if err := os.Rename(configDir, backup); err != nil {
				return fmt.Errorf("backup config dir: %w", err)
			}
			fmt.Printf("Backed up %s to %s\n", configDir, backup)
		} else {
			// It's a file where a directory should be
			if err := os.Rename(configDir, backup); err != nil {
				return fmt.Errorf("backup config path: %w", err)
			}
			fmt.Printf("Backed up file %s to %s\n", configDir, backup)
		}
	}

	// Also handle case where config.json itself is a directory
	if info, err := os.Stat(configPath); err == nil && info.IsDir() {
		backup := configPath + ".backup." + time.Now().Format("20060102-150405")
		if err := os.Rename(configPath, backup); err != nil {
			return fmt.Errorf("backup config.json dir: %w", err)
		}
		fmt.Printf("Backed up directory %s to %s\n", configPath, backup)
	}

	// Remove any remaining files
	if err := os.RemoveAll(configDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove config dir: %w", err)
	}

	// Create fresh config
	cfg, err := InitConfig()
	if err != nil {
		return err
	}

	// Restore derived key if we preserved it
	if existingDerivedKey != "" {
		cfg.DerivedKey = existingDerivedKey
		if err := SaveConfig(cfg); err != nil {
			return fmt.Errorf("save config with preserved key: %w", err)
		}
		fmt.Println("Restored existing encryption key.")
	}

	fmt.Printf("\nDevice ID: %s\n", cfg.DeviceID)
	fmt.Println("Configuration reset successfully!")

	return nil
}
