// ABOUTME: Seed rotation command for recovering from compromised seeds.
// ABOUTME: Re-encrypts all data with new keys and migrates account.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"

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

	fmt.Println("\nStarting rotation workflow...")
	ctx := context.Background()
	if err := executeRotation(ctx, config, oldKeys, newKeys); err != nil {
		return fmt.Errorf("rotation failed: %w", err)
	}

	fmt.Println("\nRotation completed successfully!")
	fmt.Printf("New user_id: %s\n", newKeys.UserID())
	fmt.Println("\nIMPORTANT: Save your new seed phrase securely.")
	fmt.Println("All devices have been migrated to the new account.")
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

	fmt.Println("\nThis command will:")
	fmt.Println("  - Pull all encrypted data from server using old keys")
	fmt.Println("  - Decrypt and re-encrypt all records with new keys")
	fmt.Println("  - Push re-encrypted data to server under new user_id")
	fmt.Println("  - Call migration endpoint to transfer devices")
	fmt.Println("  - Verify migration success")
}

func executeRotation(ctx context.Context, cfg rotateConfig, oldKeys, newKeys vault.Keys) error {
	pullResp, oldToken, err := pullOldData(ctx, cfg, oldKeys)
	if err != nil {
		return err
	}

	reencryptedItems, err := reencryptChanges(pullResp.Items, oldKeys, newKeys, newKeys.UserID())
	if err != nil {
		return fmt.Errorf("re-encrypt: %w", err)
	}
	fmt.Printf("Re-encrypted %d changes\n", len(reencryptedItems))

	if err := pushNewData(ctx, cfg, newKeys, reencryptedItems); err != nil {
		return err
	}

	if err := migrateDevices(ctx, cfg.serverURL, oldToken, oldKeys.UserID(), newKeys.UserID()); err != nil {
		return err
	}

	return verifyMigration(ctx, cfg, newKeys)
}

func pullOldData(ctx context.Context, cfg rotateConfig, oldKeys vault.Keys) (vault.PullResp, string, error) {
	signer, err := generateEphemeralSSHKey()
	if err != nil {
		return vault.PullResp{}, "", fmt.Errorf("generate ssh key: %w", err)
	}

	authClient := vault.NewAuthClient(cfg.serverURL)
	fmt.Println("Authenticating with old credentials...")
	oldToken, err := authClient.LoginWithSigner(ctx, oldKeys.UserID(), signer, true)
	if err != nil {
		return vault.PullResp{}, "", fmt.Errorf("login with old keys: %w", err)
	}

	client := vault.NewClient(vault.SyncConfig{
		BaseURL:   cfg.serverURL,
		DeviceID:  "rotation-device",
		AuthToken: oldToken.Token,
	})

	fmt.Println("Pulling all encrypted data from server...")
	pullResp, err := client.Pull(ctx, oldKeys.UserID(), 0)
	if err != nil {
		return vault.PullResp{}, "", fmt.Errorf("pull data: %w", err)
	}
	fmt.Printf("Pulled %d changes\n", len(pullResp.Items))
	return pullResp, oldToken.Token, nil
}

func pushNewData(ctx context.Context, cfg rotateConfig, newKeys vault.Keys, items []vault.PushItem) error {
	signer, err := generateEphemeralSSHKey()
	if err != nil {
		return fmt.Errorf("generate ssh key: %w", err)
	}

	authClient := vault.NewAuthClient(cfg.serverURL)
	fmt.Println("Registering new user identity...")
	if err := authClient.RegisterAuthorizedKeyWithDevice(
		ctx,
		newKeys.UserID(),
		string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		"rotation-device",
	); err != nil {
		return fmt.Errorf("register new user: %w", err)
	}

	newToken, err := authClient.LoginWithSigner(ctx, newKeys.UserID(), signer, false)
	if err != nil {
		return fmt.Errorf("login with new keys: %w", err)
	}

	client := vault.NewClient(vault.SyncConfig{
		BaseURL:   cfg.serverURL,
		DeviceID:  "rotation-device",
		AuthToken: newToken.Token,
	})

	fmt.Println("Pushing re-encrypted data to server...")
	if len(items) > 0 {
		pushResp, err := client.Push(ctx, newKeys.UserID(), items)
		if err != nil {
			return fmt.Errorf("push data: %w", err)
		}
		fmt.Printf("Pushed %d changes (acked: %d)\n", len(items), len(pushResp.Ack))
	}
	return nil
}

func migrateDevices(ctx context.Context, serverURL, authToken, oldUserID, newUserID string) error {
	fmt.Println("Migrating devices to new account...")
	if err := callMigrateEndpoint(ctx, serverURL, authToken, oldUserID, newUserID); err != nil {
		return fmt.Errorf("migrate devices: %w", err)
	}
	return nil
}

func verifyMigration(ctx context.Context, cfg rotateConfig, newKeys vault.Keys) error {
	signer, err := generateEphemeralSSHKey()
	if err != nil {
		return fmt.Errorf("generate verify key: %w", err)
	}

	authClient := vault.NewAuthClient(cfg.serverURL)
	token, err := authClient.LoginWithSigner(ctx, newKeys.UserID(), signer, true)
	if err != nil {
		return fmt.Errorf("verify login: %w", err)
	}

	client := vault.NewClient(vault.SyncConfig{
		BaseURL:   cfg.serverURL,
		DeviceID:  "rotation-verify",
		AuthToken: token.Token,
	})

	fmt.Println("Verifying migration...")
	verifyResp, err := client.Pull(ctx, newKeys.UserID(), 0)
	if err != nil {
		return fmt.Errorf("verify pull: %w", err)
	}
	fmt.Printf("Verification: %d changes available under new user_id\n", len(verifyResp.Items))
	return nil
}

func generateEphemeralSSHKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

func reencryptChanges(items []vault.PullItem, oldKeys, newKeys vault.Keys, newUserID string) ([]vault.PushItem, error) {
	result := make([]vault.PushItem, 0, len(items))

	for _, item := range items {
		oldAAD := []byte("v1|" + oldKeys.UserID() + "|" + item.DeviceID + "|" + item.ChangeID + "|" + item.Entity)
		plaintext, err := vault.Decrypt(oldKeys.EncKey, item.Env, oldAAD)
		if err != nil {
			return nil, fmt.Errorf("decrypt change %s: %w", item.ChangeID, err)
		}

		var change vault.Change
		if err := json.Unmarshal(plaintext, &change); err != nil {
			return nil, fmt.Errorf("unmarshal change: %w", err)
		}

		newChangeBytes, err := json.Marshal(change)
		if err != nil {
			return nil, fmt.Errorf("marshal change: %w", err)
		}

		newAAD := change.AAD(newUserID, "rotation-device")
		newEnv, err := vault.Encrypt(newKeys.EncKey, newChangeBytes, newAAD)
		if err != nil {
			return nil, fmt.Errorf("encrypt change: %w", err)
		}

		result = append(result, vault.PushItem{
			ChangeID: change.ChangeID,
			Entity:   change.Entity,
			TS:       change.TS.Unix(),
			Env:      newEnv,
		})
	}

	return result, nil
}

func callMigrateEndpoint(ctx context.Context, serverURL, authToken, oldUserID, newUserID string) error {
	reqBody := map[string]any{
		"old_user_id": oldUserID,
		"new_user_id": newUserID,
		"confirm":     true,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/account/migrate", bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return fmt.Errorf("migration failed: %s", errResp.Error)
		}
		return fmt.Errorf("migration failed: %s", resp.Status)
	}

	var migrateResp struct {
		OK              bool  `json:"ok"`
		MigratedDevices int64 `json:"migrated_devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&migrateResp); err != nil {
		return err
	}

	fmt.Printf("Migrated %d devices\n", migrateResp.MigratedDevices)
	return nil
}
