package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/ssh"

	"suitesync/internal/pocketbase"
	"suitesync/vault"
)

func TestSyncEndToEnd(t *testing.T) {
	env := newServerTestEnv(t)
	change := env.pushChange(t, "device-a")
	env.pullChangeOnSecondDevice(t, "device-b", change.ChangeID)
}

type serverTestEnv struct {
	t      *testing.T
	ctx    context.Context
	dir    string
	server *httptest.Server
	srv    *Server
	keys   vault.Keys
	userID string
	token  string
}

func newServerTestEnv(t *testing.T) *serverTestEnv {
	return newServerTestEnvWithPB(t, pocketbase.NoopClient{})
}

func newServerTestEnvWithPB(t *testing.T, pb pocketbase.Client) *serverTestEnv {
	ctx := context.Background()
	dir := t.TempDir()
	db := openTestDatabase(t, filepath.Join(dir, "syncvault.sqlite"))
	srv := &Server{
		db:       db,
		pbClient: pb,
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
	migrateServer(t, srv)
	ts := startTestServer(t, srv)
	keys, signer := generateKeysAndSigner(t)
	if init, ok := pb.(pocketbaseAccountInitializer); ok {
		init.ensureAccount(keys.UserID())
	}
	token := loginForToken(t, ts.URL, ctx, keys, signer)

	return &serverTestEnv{
		t:      t,
		ctx:    ctx,
		dir:    dir,
		server: ts,
		srv:    srv,
		keys:   keys,
		userID: keys.UserID(),
		token:  token,
	}
}

func openTestDatabase(t *testing.T, path string) *sql.DB {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if cerr := db.Close(); cerr != nil {
			t.Fatalf("close db: %v", cerr)
		}
	})
	return db
}

func migrateServer(t *testing.T, srv *Server) {
	if err := srv.migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func startTestServer(t *testing.T, srv *Server) *httptest.Server {
	ts := httptest.NewServer(srv.handler())
	t.Cleanup(ts.Close)
	return ts
}

func generateKeysAndSigner(t *testing.T) (vault.Keys, ssh.Signer) {
	_, seedPhrase, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	seed, err := vault.ParseSeedPhrase(seedPhrase)
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	keys, err := vault.DeriveKeys(seed, "", vault.DefaultKDFParams())
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ssh key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return keys, signer
}

func loginForToken(t *testing.T, baseURL string, ctx context.Context, keys vault.Keys, signer ssh.Signer) string {
	authClient := vault.NewAuthClient(baseURL)
	token, err := authClient.LoginWithSigner(ctx, keys.UserID(), signer, true)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return token.Token
}

type pocketbaseAccountInitializer interface {
	ensureAccount(userID string)
}

func (e *serverTestEnv) pushChange(t *testing.T, deviceID string) vault.Change {
	store := openTestStore(t, filepath.Join(e.dir, deviceID+".sqlite"))
	defer closeTestStore(t, store)

	change, err := vault.NewChange("todo", "todo-1", vault.OpUpsert, map[string]any{"text": "integration"})
	if err != nil {
		t.Fatalf("new change: %v", err)
	}
	changeBytes, err := json.Marshal(change)
	if err != nil {
		t.Fatalf("marshal change: %v", err)
	}
	env, err := vault.Encrypt(e.keys.EncKey, changeBytes, change.AAD(e.userID, deviceID))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := store.EnqueueEncryptedChange(e.ctx, change, e.userID, deviceID, env); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	client := vault.NewClient(vault.SyncConfig{BaseURL: e.server.URL, DeviceID: deviceID, AuthToken: e.token})
	var applied []vault.Change
	if err := vault.Sync(e.ctx, store, client, e.keys, func(ctx context.Context, c vault.Change) error {
		applied = append(applied, c)
		return nil
	}); err != nil {
		t.Fatalf("sync push: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("expected 1 applied change on push device, got %d", len(applied))
	}
	if items, err := store.DequeueBatch(e.ctx, 10); err != nil {
		t.Fatalf("dequeue after push: %v", err)
	} else if len(items) != 0 {
		t.Fatalf("expected empty outbox, got %d", len(items))
	}
	return change
}

func (e *serverTestEnv) pullChangeOnSecondDevice(t *testing.T, deviceID, expectedChangeID string) {
	store := openTestStore(t, filepath.Join(e.dir, deviceID+".sqlite"))
	defer closeTestStore(t, store)

	client := vault.NewClient(vault.SyncConfig{BaseURL: e.server.URL, DeviceID: deviceID, AuthToken: e.token})
	var applied []vault.Change
	if err := vault.Sync(e.ctx, store, client, e.keys, func(ctx context.Context, c vault.Change) error {
		applied = append(applied, c)
		return nil
	}); err != nil {
		t.Fatalf("sync pull: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("expected 1 applied change on pull device, got %d", len(applied))
	}
	if applied[0].ChangeID != expectedChangeID {
		t.Fatalf("unexpected change id %s", applied[0].ChangeID)
	}
}

func openTestStore(t *testing.T, path string) *vault.Store {
	store, err := vault.OpenStore(path)
	if err != nil {
		t.Fatalf("open store %s: %v", path, err)
	}
	return store
}

func closeTestStore(t *testing.T, store *vault.Store) {
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
}

func TestPushIncrementsPocketBaseUsage(t *testing.T) {
	pb := &mockPocketBaseClient{}
	env := newServerTestEnvWithPB(t, pb)
	env.pushChange(t, "device-a")
	if len(pb.increments) != 1 {
		t.Fatalf("expected 1 usage increment, got %d", len(pb.increments))
	}
	call := pb.increments[0]
	if call.userID != env.userID {
		t.Fatalf("usage recorded for wrong user: %s", call.userID)
	}
	if call.changes != 1 {
		t.Fatalf("expected 1 change recorded, got %d", call.changes)
	}
}

func TestVerifyFailsWhenPocketBaseInactive(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := openTestDatabase(t, filepath.Join(dir, "syncvault.sqlite"))

	pb := &mockPocketBaseClient{
		account:    pocketbase.AccountInfo{Active: false},
		accountSet: true,
	}

	srv := &Server{db: db, pbClient: pb}
	migrateServer(t, srv)

	userID, chID, sigB64 := setupTestDeviceAndChallenge(t, db)

	resp, status, err := srv.processVerify(ctx, verifyReq{
		UserID:       userID,
		ChallengeID:  chID,
		SignatureB64: sigB64,
	})
	if err == nil || status != http.StatusForbidden {
		t.Fatalf("expected forbidden from pocketbase denial, got status=%d err=%v resp=%+v", status, err, resp)
	}
}

func setupTestDeviceAndChallenge(t *testing.T, db *sql.DB) (userID, chID, sigB64 string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	userID = "user-test"
	deviceID := "device-test"
	now := time.Now().Unix()

	if _, err := db.Exec(`INSERT INTO users(user_id, created_at) VALUES(?,?)`, userID, now); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO devices(device_id, user_id, ssh_pubkey, ssh_pubkey_fp, name, created_at) VALUES(?,?,?,?,?,?)`,
		deviceID, userID, pubStr, fp, "test-device", now); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	chID = "challenge-1"
	challenge := []byte("challenge-bytes")
	if _, err := db.Exec(`INSERT INTO challenges(challenge_id, user_id, challenge, expires_at) VALUES(?,?,?,?)`,
		chID, userID, challenge, time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatalf("insert challenge: %v", err)
	}

	sig, _ := signer.Sign(rand.Reader, challenge)
	sigB64 = base64.StdEncoding.EncodeToString(ssh.Marshal(sig))
	return userID, chID, sigB64
}

type mockPocketBaseClient struct {
	account    pocketbase.AccountInfo
	accountSet bool
	accountErr error
	increments []usageRecord
}

type usageRecord struct {
	userID  string
	changes int
}

func (m *mockPocketBaseClient) GetAccountByUserID(ctx context.Context, userID string) (pocketbase.AccountInfo, error) {
	if m.accountErr != nil {
		return pocketbase.AccountInfo{}, m.accountErr
	}
	if !m.accountSet {
		return pocketbase.AccountInfo{UserID: userID, Active: true}, nil
	}
	acc := m.account
	if acc.UserID == "" {
		acc.UserID = userID
	}
	if acc.ID == "" {
		acc.ID = "acct-" + userID
	}
	return acc, nil
}

func (m *mockPocketBaseClient) IncrementUsage(ctx context.Context, userID string, changes int) error {
	m.increments = append(m.increments, usageRecord{userID: userID, changes: changes})
	return nil
}

func (m *mockPocketBaseClient) ensureAccount(userID string) {
	if !m.accountSet {
		m.account = pocketbase.AccountInfo{UserID: userID, Active: true}
		m.accountSet = true
	}
}

func (e *serverTestEnv) setRateLimit(interval time.Duration, burst int) {
	e.srv.limiters.setConfig(interval, burst)
}

func TestCleanupPurgesExpiredTokensAndChallenges(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "test.sqlite"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close db: %v", err)
		}
	}()

	srv := &Server{db: db, pbClient: pocketbase.NoopClient{}}
	if err := srv.migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Now().Unix()
	expired := now - 3600 // 1 hour ago
	valid := now + 3600   // 1 hour from now

	// Insert expired and valid tokens
	if _, err := db.Exec(`INSERT INTO tokens(token_hash, user_id, expires_at) VALUES('expired1', 'user1', ?)`, expired); err != nil {
		t.Fatalf("insert expired token: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tokens(token_hash, user_id, expires_at) VALUES('valid1', 'user1', ?)`, valid); err != nil {
		t.Fatalf("insert valid token: %v", err)
	}

	// Insert expired and valid challenges
	if _, err := db.Exec(`INSERT INTO challenges(challenge_id, user_id, challenge, expires_at) VALUES('ch-expired', 'user1', X'00', ?)`, expired); err != nil {
		t.Fatalf("insert expired challenge: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO challenges(challenge_id, user_id, challenge, expires_at) VALUES('ch-valid', 'user1', X'00', ?)`, valid); err != nil {
		t.Fatalf("insert valid challenge: %v", err)
	}

	// Run cleanup
	deleted := srv.cleanupExpired(ctx)

	if deleted.tokens != 1 {
		t.Errorf("expected 1 expired token deleted, got %d", deleted.tokens)
	}
	if deleted.challenges != 1 {
		t.Errorf("expected 1 expired challenge deleted, got %d", deleted.challenges)
	}

	// Verify valid records remain
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&count); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 token remaining, got %d", count)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM challenges`).Scan(&count); err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 challenge remaining, got %d", count)
	}
}

func TestRateLimitRejects429(t *testing.T) {
	env := newServerTestEnv(t)

	// Configure tight rate limit for testing: 1 request per second, burst of 1
	env.setRateLimit(time.Second, 1)

	client := &http.Client{}

	// First request should succeed
	req1, _ := http.NewRequest("GET", env.server.URL+"/v1/sync/pull?user_id="+env.userID+"&since=0", nil)
	req1.Header.Set("Authorization", "Bearer "+env.token)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if err := resp1.Body.Close(); err != nil {
		t.Fatalf("close resp1 body: %v", err)
	}
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request expected 200, got %d", resp1.StatusCode)
	}

	// Rapid second request should be rate limited
	req2, _ := http.NewRequest("GET", env.server.URL+"/v1/sync/pull?user_id="+env.userID+"&since=0", nil)
	req2.Header.Set("Authorization", "Bearer "+env.token)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if err := resp2.Body.Close(); err != nil {
		t.Fatalf("close resp2 body: %v", err)
	}
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request expected 429, got %d", resp2.StatusCode)
	}
}

func TestMultipleDevicesCanAuthenticate(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := openTestDatabase(t, filepath.Join(dir, "syncvault.sqlite"))
	srv := &Server{
		db:       db,
		pbClient: pocketbase.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
	migrateServer(t, srv)
	ts := startTestServer(t, srv)

	keys, _ := generateKeysAndSigner(t)
	userID := keys.UserID()

	// Register device A
	_, privA, _ := ed25519.GenerateKey(rand.Reader)
	signerA, _ := ssh.NewSignerFromKey(privA)
	tokenA := registerAndLogin(t, ts.URL, ctx, userID, signerA, "device-a")

	// Register device B (should NOT invalidate device A)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	signerB, _ := ssh.NewSignerFromKey(privB)
	tokenB := registerAndLogin(t, ts.URL, ctx, userID, signerB, "device-b")

	// Both tokens should work
	client := &http.Client{}

	reqA, _ := http.NewRequest("GET", ts.URL+"/v1/sync/pull?user_id="+userID+"&since=0", nil)
	reqA.Header.Set("Authorization", "Bearer "+tokenA)
	respA, err := client.Do(reqA)
	if err != nil {
		t.Fatalf("device A request: %v", err)
	}
	if err := respA.Body.Close(); err != nil {
		t.Fatalf("close respA body: %v", err)
	}
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("device A expected 200, got %d", respA.StatusCode)
	}

	reqB, _ := http.NewRequest("GET", ts.URL+"/v1/sync/pull?user_id="+userID+"&since=0", nil)
	reqB.Header.Set("Authorization", "Bearer "+tokenB)
	respB, err := client.Do(reqB)
	if err != nil {
		t.Fatalf("device B request: %v", err)
	}
	if err := respB.Body.Close(); err != nil {
		t.Fatalf("close respB body: %v", err)
	}
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("device B expected 200, got %d", respB.StatusCode)
	}
}

func registerAndLogin(t *testing.T, baseURL string, ctx context.Context, userID string, signer ssh.Signer, deviceName string) string {
	authClient := vault.NewAuthClient(baseURL)

	// Register with device name
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := authClient.RegisterAuthorizedKeyWithDevice(ctx, userID, pubStr, deviceName); err != nil {
		t.Fatalf("register %s: %v", deviceName, err)
	}

	// Get challenge and login
	ch, err := authClient.Challenge(ctx, userID)
	if err != nil {
		t.Fatalf("challenge %s: %v", deviceName, err)
	}
	sig, _ := signer.Sign(rand.Reader, ch.Data)
	sigB64 := base64.StdEncoding.EncodeToString(ssh.Marshal(sig))
	token, err := authClient.Verify(ctx, userID, ch.ID, sigB64)
	if err != nil {
		t.Fatalf("verify %s: %v", deviceName, err)
	}
	return token.Token
}

func TestListDevices(t *testing.T) {
	env := newServerTestEnv(t)

	// Register a second device
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	signerB, _ := ssh.NewSignerFromKey(privB)
	registerAndLogin(t, env.server.URL, env.ctx, env.userID, signerB, "second-device")

	// List devices
	client := &http.Client{}
	req, _ := http.NewRequest("GET", env.server.URL+"/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+env.token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close resp body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
			Name     string `json:"name"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(body.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(body.Devices))
	}
}

func TestRevokeDevice(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := openTestDatabase(t, filepath.Join(dir, "syncvault.sqlite"))
	srv := &Server{
		db:       db,
		pbClient: pocketbase.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
	migrateServer(t, srv)
	ts := startTestServer(t, srv)

	keys, _ := generateKeysAndSigner(t)
	userID := keys.UserID()

	// Register device A and B
	_, privA, _ := ed25519.GenerateKey(rand.Reader)
	signerA, _ := ssh.NewSignerFromKey(privA)
	tokenA := registerAndLogin(t, ts.URL, ctx, userID, signerA, "device-a")

	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	signerB, _ := ssh.NewSignerFromKey(privB)
	tokenB := registerAndLogin(t, ts.URL, ctx, userID, signerB, "device-b")

	// Get device B's ID
	deviceBID := getSecondDeviceID(t, ts.URL, tokenB)

	// Revoke device B using device A's token
	revokeDevice(t, ts.URL, tokenA, deviceBID)

	// Verify device B token no longer works (401)
	verifyTokenStatus(t, ts.URL, tokenB, userID, http.StatusUnauthorized)

	// Verify device A token still works (200)
	verifyTokenStatus(t, ts.URL, tokenA, userID, http.StatusOK)
}

func getSecondDeviceID(t *testing.T, baseURL, token string) string {
	t.Helper()
	client := &http.Client{}
	req, _ := http.NewRequest("GET", baseURL+"/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response: %v", err)
		}
	}()

	var body struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(body.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(body.Devices))
	}
	return body.Devices[1].DeviceID
}

func revokeDevice(t *testing.T, baseURL, token, deviceID string) {
	t.Helper()
	client := &http.Client{}
	req, _ := http.NewRequest("DELETE", baseURL+"/v1/devices/"+deviceID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke expected 200, got %d", resp.StatusCode)
	}
}

func verifyTokenStatus(t *testing.T, baseURL, token, userID string, expectedStatus int) {
	t.Helper()
	client := &http.Client{}
	req, _ := http.NewRequest("GET", baseURL+"/v1/sync/pull?user_id="+userID+"&since=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("verify token request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response: %v", err)
		}
	}()
	if resp.StatusCode != expectedStatus {
		t.Fatalf("expected status %d, got %d", expectedStatus, resp.StatusCode)
	}
}

func TestSnapshotAndPrune(t *testing.T) {
	env := newServerTestEnv(t)
	pushTestChanges(t, env, 5)
	createTestSnapshot(t, env)
	verifySnapshotInPull(t, env)
}

func pushTestChanges(t *testing.T, env *serverTestEnv, count int) {
	t.Helper()
	client := vault.NewClient(vault.SyncConfig{BaseURL: env.server.URL, DeviceID: "device-a", AuthToken: env.token})
	for i := 0; i < count; i++ {
		change, err := vault.NewChange("todo", fmt.Sprintf("item-%d", i), vault.OpUpsert, map[string]any{"n": i})
		if err != nil {
			t.Fatalf("create change: %v", err)
		}
		changeBytes, err := json.Marshal(change)
		if err != nil {
			t.Fatalf("marshal change: %v", err)
		}
		envl, err := vault.Encrypt(env.keys.EncKey, changeBytes, change.AAD(env.userID, "device-a"))
		if err != nil {
			t.Fatalf("encrypt change: %v", err)
		}
		_, err = client.Push(env.ctx, env.userID, []vault.PushItem{{
			ChangeID: change.ChangeID,
			Entity:   change.Entity,
			TS:       change.TS.Unix(),
			Env:      envl,
		}})
		if err != nil {
			t.Fatalf("push change %d: %v", i, err)
		}
	}
}

func createTestSnapshot(t *testing.T, env *serverTestEnv) {
	t.Helper()
	payload := []byte(`[{"entity_id":"item-0"},{"entity_id":"item-1"}]`)
	snapshotEnv, err := vault.Encrypt(env.keys.EncKey, payload, []byte("snapshot:"+env.userID+":todo"))
	if err != nil {
		t.Fatalf("encrypt snapshot: %v", err)
	}

	reqBody := map[string]any{
		"user_id": env.userID,
		"entity":  "todo",
		"env":     map[string]string{"nonce_b64": snapshotEnv.NonceB64, "ct_b64": snapshotEnv.CTB64},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal snapshot req: %v", err)
	}
	httpReq, err := http.NewRequest("POST", env.server.URL+"/v1/sync/snapshot", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create snapshot request: %v", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+env.token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("snapshot request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func verifySnapshotInPull(t *testing.T, env *serverTestEnv) {
	t.Helper()
	client := vault.NewClient(vault.SyncConfig{BaseURL: env.server.URL, DeviceID: "device-b", AuthToken: env.token})
	pullResp, err := client.PullWithSnapshot(env.ctx, env.userID, 0, "todo")
	if err != nil {
		t.Fatalf("pull with snapshot: %v", err)
	}
	if pullResp.Snapshot == nil {
		t.Fatalf("expected snapshot in response")
	}
	if pullResp.Snapshot.MinSeq != 5 {
		t.Errorf("expected snapshot min_seq=5, got %d", pullResp.Snapshot.MinSeq)
	}
}
