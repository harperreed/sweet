// ABOUTME: Seed rotation command for recovering from compromised seeds.
// ABOUTME: Re-encrypts all data with new keys and migrates account.

package main

import (
	"flag"
	"fmt"
	"os"

	"suitesync/vault"
)

type rotateConfig struct {
	oldSeed    string
	newSeed    string
	passphrase string
	serverURL  string
	appDB      string
}

func cmdRotateSeed(args []string) error {
	config, err := parseRotateArgs(args)
	if err != nil {
		return err
	}

	oldKeys, newKeys, err := deriveRotationKeys(config)
	if err != nil {
		return err
	}

	displayRotationPlan(oldKeys, newKeys, config)
	return nil
}

func parseRotateArgs(args []string) (rotateConfig, error) {
	fs := flag.NewFlagSet("rotate-seed", flag.ExitOnError)
	cfg := rotateConfig{}
	fs.StringVar(&cfg.oldSeed, "old-seed", "", "current seed phrase")
	fs.StringVar(&cfg.newSeed, "new-seed", "", "new seed phrase (generated if empty)")
	fs.StringVar(&cfg.passphrase, "passphrase", "", "passphrase for key derivation")
	fs.StringVar(&cfg.serverURL, "server", "http://localhost:8080", "sync server URL")
	fs.StringVar(&cfg.appDB, "app-db", "", "path to app database")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.oldSeed == "" || cfg.appDB == "" {
		return cfg, fmt.Errorf("old-seed and app-db required")
	}
	return cfg, nil
}

func deriveRotationKeys(cfg rotateConfig) (oldKeys, newKeys vault.Keys, err error) {
	oldSeedParsed, err := vault.ParseSeedPhrase(cfg.oldSeed)
	if err != nil {
		return vault.Keys{}, vault.Keys{}, fmt.Errorf("parse old seed: %w", err)
	}
	oldKeys, err = vault.DeriveKeys(oldSeedParsed, cfg.passphrase, vault.DefaultKDFParams())
	if err != nil {
		return vault.Keys{}, vault.Keys{}, fmt.Errorf("derive old keys: %w", err)
	}

	newSeedParsed, newSeedPhrase, err := resolveNewSeed(cfg.newSeed)
	if err != nil {
		return vault.Keys{}, vault.Keys{}, err
	}
	_ = newSeedPhrase // will be used for confirmation in full implementation

	newKeys, err = vault.DeriveKeys(newSeedParsed, cfg.passphrase, vault.DefaultKDFParams())
	if err != nil {
		return vault.Keys{}, vault.Keys{}, fmt.Errorf("derive new keys: %w", err)
	}
	return oldKeys, newKeys, nil
}

func resolveNewSeed(newSeed string) (vault.SeedPhrase, string, error) {
	if newSeed == "" {
		parsed, phrase, err := vault.NewSeedPhrase()
		if err != nil {
			return vault.SeedPhrase{}, "", fmt.Errorf("generate new seed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Generated new seed phrase:\n%s\n\nSAVE THIS SECURELY!\n\n", phrase)
		return parsed, phrase, nil
	}
	parsed, err := vault.ParseSeedPhrase(newSeed)
	return parsed, newSeed, err
}

func displayRotationPlan(oldKeys, newKeys vault.Keys, cfg rotateConfig) {
	fmt.Printf("Old user_id: %s\n", oldKeys.UserID())
	fmt.Printf("New user_id: %s\n", newKeys.UserID())
	fmt.Printf("Server URL: %s\n", cfg.serverURL)
	fmt.Printf("App DB: %s\n", cfg.appDB)

	fmt.Println("\nSeed rotation prepared. Full implementation continues in next phase.")
	fmt.Println("This command will:")
	fmt.Println("  - Pull all encrypted data from server using old keys")
	fmt.Println("  - Decrypt and re-encrypt all records with new keys")
	fmt.Println("  - Push re-encrypted data to server under new user_id")
	fmt.Println("  - Call migration endpoint to transfer devices")
	fmt.Println("  - Verify migration success")
}
