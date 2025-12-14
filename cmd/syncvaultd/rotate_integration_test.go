// ABOUTME: Integration test for seed rotation workflow.
// ABOUTME: Tests full rotation flow including re-encryption and device migration.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"suitesync/vault"
)

func TestSeedRotationIntegration(t *testing.T) {
	env := newServerTestEnv(t)
	pushInitialData(t, env)

	newKeys := generateNewKeysForTest(t)
	pullResp, oldToken := pullOldDataForTest(t, env)
	reencryptedItems := reencryptDataForTest(t, pullResp.Items, env.keys, newKeys)
	pushNewDataForTest(t, env, newKeys, reencryptedItems)
	migrateAccountForTest(t, env, oldToken, newKeys)
	verifyRotationForTest(t, env, newKeys, len(pullResp.Items))
}

func generateNewKeysForTest(t *testing.T) vault.Keys {
	t.Helper()
	newSeed, _, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("generate new seed: %v", err)
	}
	newKeys, err := vault.DeriveKeys(newSeed, "", vault.DefaultKDFParams())
	if err != nil {
		t.Fatalf("derive new keys: %v", err)
	}
	return newKeys
}

func pullOldDataForTest(t *testing.T, env *serverTestEnv) (vault.PullResp, string) {
	t.Helper()
	_, oldSigner := generateKeysAndSigner(t)
	authClient := vault.NewAuthClient(env.server.URL)
	oldToken, err := authClient.LoginWithSigner(env.ctx, env.userID, oldSigner, true)
	if err != nil {
		t.Fatalf("login with old keys: %v", err)
	}

	oldClient := vault.NewClient(vault.SyncConfig{
		BaseURL:   env.server.URL,
		DeviceID:  "rotation-device",
		AuthToken: oldToken.Token,
	})

	pullResp, err := oldClient.Pull(env.ctx, env.userID, 0)
	if err != nil {
		t.Fatalf("pull old data: %v", err)
	}
	if len(pullResp.Items) == 0 {
		t.Fatal("expected at least one change from initial push")
	}
	return pullResp, oldToken.Token
}

func reencryptDataForTest(t *testing.T, items []vault.PullItem, oldKeys, newKeys vault.Keys) []vault.PushItem {
	t.Helper()
	reencryptedItems, err := reencryptForNewKeys(t, items, oldKeys, newKeys)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	return reencryptedItems
}

func pushNewDataForTest(t *testing.T, env *serverTestEnv, newKeys vault.Keys, items []vault.PushItem) {
	t.Helper()
	authClient := vault.NewAuthClient(env.server.URL)
	_, newSigner := generateKeysAndSigner(t)
	if err := authClient.RegisterAuthorizedKeyWithDevice(
		env.ctx, newKeys.UserID(),
		string(ssh.MarshalAuthorizedKey(newSigner.PublicKey())),
		"rotation-device",
	); err != nil {
		t.Fatalf("register new user: %v", err)
	}

	newToken, err := authClient.LoginWithSigner(env.ctx, newKeys.UserID(), newSigner, false)
	if err != nil {
		t.Fatalf("login with new keys: %v", err)
	}

	newClient := vault.NewClient(vault.SyncConfig{
		BaseURL:   env.server.URL,
		DeviceID:  "rotation-device",
		AuthToken: newToken.Token,
	})

	pushResp, err := newClient.Push(env.ctx, newKeys.UserID(), items)
	if err != nil {
		t.Fatalf("push re-encrypted data: %v", err)
	}
	if len(pushResp.Ack) != len(items) {
		t.Errorf("expected %d acks, got %d", len(items), len(pushResp.Ack))
	}
}

func migrateAccountForTest(t *testing.T, env *serverTestEnv, oldToken string, newKeys vault.Keys) {
	t.Helper()
	if err := callMigrateAPI(env.ctx, env.server.URL, oldToken, env.userID, newKeys.UserID()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func verifyRotationForTest(t *testing.T, env *serverTestEnv, newKeys vault.Keys, expectedCount int) {
	t.Helper()
	_, newSigner := generateKeysAndSigner(t)
	authClient := vault.NewAuthClient(env.server.URL)
	newToken, err := authClient.LoginWithSigner(env.ctx, newKeys.UserID(), newSigner, true)
	if err != nil {
		t.Fatalf("verify login: %v", err)
	}

	newClient := vault.NewClient(vault.SyncConfig{
		BaseURL:   env.server.URL,
		DeviceID:  "verify-device",
		AuthToken: newToken.Token,
	})

	verifyResp, err := newClient.Pull(env.ctx, newKeys.UserID(), 0)
	if err != nil {
		t.Fatalf("verify pull: %v", err)
	}
	if len(verifyResp.Items) != expectedCount {
		t.Errorf("expected %d items after rotation, got %d", expectedCount, len(verifyResp.Items))
	}

	for _, item := range verifyResp.Items {
		verifyItemDecryption(t, item, newKeys)
	}
}

func verifyItemDecryption(t *testing.T, item vault.PullItem, newKeys vault.Keys) {
	t.Helper()
	aad := []byte("v1|" + newKeys.UserID() + "|" + item.DeviceID + "|" + item.ChangeID + "|" + item.Entity)
	plaintext, err := vault.Decrypt(newKeys.EncKey, item.Env, aad)
	if err != nil {
		t.Errorf("decrypt item %s: %v", item.ChangeID, err)
		return
	}

	var change vault.Change
	if err := json.Unmarshal(plaintext, &change); err != nil {
		t.Errorf("unmarshal change: %v", err)
	}
}

func pushInitialData(t *testing.T, env *serverTestEnv) {
	store := openTestStore(t, filepath.Join(env.dir, "device-a.sqlite"))
	defer closeTestStore(t, store)

	changes := []struct {
		entity   string
		entityID string
		payload  any
	}{
		{"todo", "todo-1", map[string]any{"text": "buy milk"}},
		{"todo", "todo-2", map[string]any{"text": "write code"}},
		{"note", "note-1", map[string]any{"content": "important note"}},
	}

	for _, tc := range changes {
		change, err := vault.NewChange(tc.entity, tc.entityID, vault.OpUpsert, tc.payload)
		if err != nil {
			t.Fatalf("new change: %v", err)
		}

		changeBytes, err := json.Marshal(change)
		if err != nil {
			t.Fatalf("marshal change: %v", err)
		}

		aad := change.AAD(env.userID, "device-a")
		envelope, err := vault.Encrypt(env.keys.EncKey, changeBytes, aad)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		if err := store.EnqueueEncryptedChange(env.ctx, change, env.userID, "device-a", envelope); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	client := vault.NewClient(vault.SyncConfig{
		BaseURL:   env.server.URL,
		DeviceID:  "device-a",
		AuthToken: env.token,
	})

	if err := vault.Sync(env.ctx, store, client, env.keys, func(ctx context.Context, c vault.Change) error {
		return nil
	}); err != nil {
		t.Fatalf("sync: %v", err)
	}
}

func reencryptForNewKeys(t *testing.T, items []vault.PullItem, oldKeys, newKeys vault.Keys) ([]vault.PushItem, error) {
	t.Helper()
	result := make([]vault.PushItem, 0, len(items))

	for _, item := range items {
		oldAAD := []byte("v1|" + oldKeys.UserID() + "|" + item.DeviceID + "|" + item.ChangeID + "|" + item.Entity)
		plaintext, err := vault.Decrypt(oldKeys.EncKey, item.Env, oldAAD)
		if err != nil {
			return nil, err
		}

		var change vault.Change
		if err := json.Unmarshal(plaintext, &change); err != nil {
			return nil, err
		}

		newChangeBytes, err := json.Marshal(change)
		if err != nil {
			return nil, err
		}

		newAAD := change.AAD(newKeys.UserID(), "rotation-device")
		newEnv, err := vault.Encrypt(newKeys.EncKey, newChangeBytes, newAAD)
		if err != nil {
			return nil, err
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

func callMigrateAPI(ctx context.Context, serverURL, authToken, oldUserID, newUserID string) error {
	reqBody := map[string]any{
		"old_user_id": oldUserID,
		"new_user_id": newUserID,
		"confirm":     true,
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := newTestRequest(ctx, "POST", serverURL+"/v1/account/migrate", jsonBytes)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error != "" {
			return err
		}
	}

	return nil
}

func newTestRequest(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	if body == nil {
		return http.NewRequestWithContext(ctx, method, url, nil)
	}
	return http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
}
