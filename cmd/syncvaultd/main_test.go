package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"

	"golang.org/x/crypto/ssh"

	pbclient "suitesync/internal/pocketbase"
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
	return newServerTestEnvWithPB(t, pbclient.NoopClient{})
}

func newServerTestEnvWithPB(t *testing.T, pb pbclient.Client) *serverTestEnv {
	ctx := context.Background()
	dir := t.TempDir()
	app := createTestApp(t, dir)
	srv := &Server{
		app:      app,
		pbClient: pb,
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
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

//nolint:unparam // dir parameter available for custom test data paths if needed.
func createTestApp(t *testing.T, _ string) core.App {
	t.Helper()
	// Create a test PocketBase app without existing test data
	testApp, err := tests.NewTestApp()
	if err != nil {
		t.Fatalf("new test app: %v", err)
	}

	// Run our custom schema migrations
	if err := runTestMigrations(testApp); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	t.Cleanup(func() {
		testApp.Cleanup()
	})

	return testApp
}

//nolint:funlen // Test migrations need to set up complete schema.
func runTestMigrations(app core.App) error {
	// Check if collections already exist (via migrations import)
	if _, err := app.FindCollectionByNameOrId("sync_users"); err == nil {
		// Collections already exist from migrations, skip manual creation
		return nil
	}

	// Create sync_users collection
	syncUsers := core.NewBaseCollection("sync_users")
	syncUsers.Fields.Add(
		&core.TextField{
			Name:     "user_id",
			Required: true,
		},
	)
	syncUsers.AddIndex("idx_sync_users_user_id", true, "user_id", "")
	if err := app.Save(syncUsers); err != nil {
		return err
	}

	// Create sync_devices collection
	syncDevices := core.NewBaseCollection("sync_devices")
	syncDevices.Fields.Add(
		&core.TextField{
			Name:     "device_id",
			Required: true,
		},
		&core.TextField{
			Name:     "user_id",
			Required: true,
		},
		&core.TextField{
			Name:     "ssh_pubkey",
			Required: true,
		},
		&core.TextField{
			Name:     "ssh_pubkey_fp",
			Required: true,
		},
		&core.TextField{
			Name: "name",
		},
		&core.NumberField{
			Name: "last_used_at",
		},
	)
	syncDevices.AddIndex("idx_sync_devices_device_id", true, "device_id", "")
	syncDevices.AddIndex("idx_sync_devices_ssh_pubkey_fp", true, "ssh_pubkey_fp", "")
	syncDevices.AddIndex("idx_sync_devices_user_id", false, "user_id", "")
	if err := app.Save(syncDevices); err != nil {
		return err
	}

	// Create sync_challenges collection
	syncChallenges := core.NewBaseCollection("sync_challenges")
	syncChallenges.Fields.Add(
		&core.TextField{
			Name:     "challenge_id",
			Required: true,
		},
		&core.TextField{
			Name:     "user_id",
			Required: true,
		},
		&core.TextField{
			Name:     "challenge",
			Required: true,
		},
		&core.NumberField{
			Name:     "expires_at",
			Required: true,
		},
	)
	syncChallenges.AddIndex("idx_sync_challenges_challenge_id", true, "challenge_id", "")
	syncChallenges.AddIndex("idx_sync_challenges_user_exp", false, "user_id, expires_at", "")
	if err := app.Save(syncChallenges); err != nil {
		return err
	}

	// Create sync_tokens collection
	syncTokens := core.NewBaseCollection("sync_tokens")
	syncTokens.Fields.Add(
		&core.TextField{
			Name:     "token_hash",
			Required: true,
		},
		&core.TextField{
			Name:     "user_id",
			Required: true,
		},
		&core.TextField{
			Name: "device_id",
		},
		&core.NumberField{
			Name:     "expires_at",
			Required: true,
		},
	)
	syncTokens.AddIndex("idx_sync_tokens_token_hash", true, "token_hash", "")
	syncTokens.AddIndex("idx_sync_tokens_device", false, "device_id", "")
	syncTokens.AddIndex("idx_sync_tokens_user_exp", false, "user_id, expires_at", "")
	if err := app.Save(syncTokens); err != nil {
		return err
	}

	// Create sync_changes collection
	syncChanges := core.NewBaseCollection("sync_changes")
	syncChanges.Fields.Add(
		&core.NumberField{
			Name:     "seq",
			Required: true,
		},
		&core.TextField{
			Name:     "user_id",
			Required: true,
		},
		&core.TextField{
			Name:     "change_id",
			Required: true,
		},
		&core.TextField{
			Name:     "device_id",
			Required: true,
		},
		&core.TextField{
			Name:     "entity",
			Required: true,
		},
		&core.NumberField{
			Name:     "ts",
			Required: true,
		},
		&core.TextField{
			Name:     "nonce_b64",
			Required: true,
		},
		&core.TextField{
			Name:     "ct_b64",
			Required: true,
		},
	)
	syncChanges.AddIndex("idx_sync_changes_user_change", true, "user_id, change_id", "")
	syncChanges.AddIndex("idx_sync_changes_user_seq", false, "user_id, seq", "")
	if err := app.Save(syncChanges); err != nil {
		return err
	}

	// Create sync_snapshots collection
	syncSnapshots := core.NewBaseCollection("sync_snapshots")
	syncSnapshots.Fields.Add(
		&core.TextField{
			Name:     "snapshot_id",
			Required: true,
		},
		&core.TextField{
			Name:     "user_id",
			Required: true,
		},
		&core.TextField{
			Name:     "entity",
			Required: true,
		},
		&core.NumberField{
			Name:     "min_seq",
			Required: true,
		},
		&core.TextField{
			Name:     "nonce_b64",
			Required: true,
		},
		&core.TextField{
			Name:     "ct_b64",
			Required: true,
		},
	)
	syncSnapshots.AddIndex("idx_sync_snapshots_snapshot_id", true, "snapshot_id", "")
	syncSnapshots.AddIndex("idx_sync_snapshots_user_entity", false, "user_id, entity", "")
	if err := app.Save(syncSnapshots); err != nil {
		return err
	}

	return nil
}

func startTestServer(t *testing.T, srv *Server) *httptest.Server {
	// Create an HTTP handler that uses our routes
	mux := http.NewServeMux()

	// Healthz
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Auth endpoints
	mux.HandleFunc("/v1/auth/register", srv.handleRegister)
	mux.HandleFunc("/v1/auth/challenge", srv.handleChallenge)
	mux.HandleFunc("/v1/auth/verify", srv.handleVerify)

	// Sync endpoints (protected)
	mux.HandleFunc("/v1/sync/push", srv.withAuth(srv.handlePush))
	mux.HandleFunc("/v1/sync/pull", srv.withAuth(srv.handlePull))
	mux.HandleFunc("/v1/sync/snapshot", srv.withAuth(srv.handleSnapshot))
	mux.HandleFunc("/v1/sync/compact", srv.withAuth(srv.handleCompact))

	// Device management (protected)
	mux.HandleFunc("/v1/devices", srv.withAuth(srv.handleListDevices))
	mux.HandleFunc("/v1/devices/", srv.withAuth(srv.handleRevokeDevice))

	// Account management (protected)
	mux.HandleFunc("/v1/account/migrate", srv.withAuth(srv.handleMigrate))

	ts := httptest.NewServer(mux)
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
	app := createTestApp(t, dir)

	pb := &mockPocketBaseClient{
		account:    pbclient.AccountInfo{Active: false},
		accountSet: true,
	}

	srv := &Server{app: app, pbClient: pb}

	userID, chID, sigB64 := setupTestDeviceAndChallenge(t, app)

	resp, status, err := srv.processVerify(ctx, verifyReq{
		UserID:       userID,
		ChallengeID:  chID,
		SignatureB64: sigB64,
	})
	if err == nil || status != http.StatusForbidden {
		t.Fatalf("expected forbidden from pocketbase denial, got status=%d err=%v resp=%+v", status, err, resp)
	}
}

func setupTestDeviceAndChallenge(t *testing.T, app core.App) (userID, chID, sigB64 string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	userID = "user-test"
	deviceID := "device-test"

	// Create user
	usersCol, err := app.FindCollectionByNameOrId("sync_users")
	if err != nil {
		t.Fatalf("find users collection: %v", err)
	}
	userRecord := core.NewRecord(usersCol)
	userRecord.Set("user_id", userID)
	if err := app.Save(userRecord); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	// Create device
	devicesCol, err := app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		t.Fatalf("find devices collection: %v", err)
	}
	deviceRecord := core.NewRecord(devicesCol)
	deviceRecord.Set("device_id", deviceID)
	deviceRecord.Set("user_id", userID)
	deviceRecord.Set("ssh_pubkey", pubStr)
	deviceRecord.Set("ssh_pubkey_fp", fp)
	deviceRecord.Set("name", "test-device")
	if err := app.Save(deviceRecord); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	// Create challenge
	chID = "challenge-1"
	challenge := []byte("challenge-bytes")
	challengesCol, err := app.FindCollectionByNameOrId("sync_challenges")
	if err != nil {
		t.Fatalf("find challenges collection: %v", err)
	}
	challengeRecord := core.NewRecord(challengesCol)
	challengeRecord.Set("challenge_id", chID)
	challengeRecord.Set("user_id", userID)
	challengeRecord.Set("challenge", base64.StdEncoding.EncodeToString(challenge))
	challengeRecord.Set("expires_at", time.Now().Add(time.Minute).Unix())
	if err := app.Save(challengeRecord); err != nil {
		t.Fatalf("insert challenge: %v", err)
	}

	sig, _ := signer.Sign(rand.Reader, challenge)
	sigB64 = base64.StdEncoding.EncodeToString(ssh.Marshal(sig))
	return userID, chID, sigB64
}

type mockPocketBaseClient struct {
	account    pbclient.AccountInfo
	accountSet bool
	accountErr error
	increments []usageRecord
}

type usageRecord struct {
	userID  string
	changes int
}

func (m *mockPocketBaseClient) GetAccountByUserID(ctx context.Context, userID string) (pbclient.AccountInfo, error) {
	if m.accountErr != nil {
		return pbclient.AccountInfo{}, m.accountErr
	}
	if !m.accountSet {
		return pbclient.AccountInfo{UserID: userID, Active: true}, nil
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

func (m *mockPocketBaseClient) MigrateUserID(ctx context.Context, oldUserID, newUserID string) error {
	return nil
}

func (m *mockPocketBaseClient) ensureAccount(userID string) {
	if !m.accountSet {
		m.account = pbclient.AccountInfo{UserID: userID, Active: true}
		m.accountSet = true
	}
}

func (e *serverTestEnv) setRateLimit(interval time.Duration, burst int) {
	e.srv.limiters.setConfig(interval, burst)
}

//nolint:funlen // Cleanup test needs comprehensive setup and verification.
func TestCleanupPurgesExpiredTokensAndChallenges(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	app := createTestApp(t, dir)

	srv := &Server{app: app, pbClient: pbclient.NoopClient{}}

	now := time.Now().Unix()
	expired := now - 3600 // 1 hour ago
	valid := now + 3600   // 1 hour from now

	// Insert expired and valid tokens
	tokensCol, err := app.FindCollectionByNameOrId("sync_tokens")
	if err != nil {
		t.Fatalf("find tokens collection: %v", err)
	}

	expiredToken := core.NewRecord(tokensCol)
	expiredToken.Set("token_hash", "expired1")
	expiredToken.Set("user_id", "user1")
	expiredToken.Set("device_id", "")
	expiredToken.Set("expires_at", expired)
	if err := app.Save(expiredToken); err != nil {
		t.Fatalf("insert expired token: %v", err)
	}

	validToken := core.NewRecord(tokensCol)
	validToken.Set("token_hash", "valid1")
	validToken.Set("user_id", "user1")
	validToken.Set("device_id", "")
	validToken.Set("expires_at", valid)
	if err := app.Save(validToken); err != nil {
		t.Fatalf("insert valid token: %v", err)
	}

	// Insert expired and valid challenges
	challengesCol, err := app.FindCollectionByNameOrId("sync_challenges")
	if err != nil {
		t.Fatalf("find challenges collection: %v", err)
	}

	expiredChallenge := core.NewRecord(challengesCol)
	expiredChallenge.Set("challenge_id", "ch-expired")
	expiredChallenge.Set("user_id", "user1")
	expiredChallenge.Set("challenge", base64.StdEncoding.EncodeToString([]byte{0x00}))
	expiredChallenge.Set("expires_at", expired)
	if err := app.Save(expiredChallenge); err != nil {
		t.Fatalf("insert expired challenge: %v", err)
	}

	validChallenge := core.NewRecord(challengesCol)
	validChallenge.Set("challenge_id", "ch-valid")
	validChallenge.Set("user_id", "user1")
	validChallenge.Set("challenge", base64.StdEncoding.EncodeToString([]byte{0x00}))
	validChallenge.Set("expires_at", valid)
	if err := app.Save(validChallenge); err != nil {
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
	remainingTokens, err := app.FindRecordsByFilter(tokensCol, "", "", 100, 0, nil)
	if err != nil {
		t.Fatalf("query tokens: %v", err)
	}
	if len(remainingTokens) != 1 {
		t.Errorf("expected 1 token remaining, got %d", len(remainingTokens))
	}

	remainingChallenges, err := app.FindRecordsByFilter(challengesCol, "", "", 100, 0, nil)
	if err != nil {
		t.Fatalf("query challenges: %v", err)
	}
	if len(remainingChallenges) != 1 {
		t.Errorf("expected 1 challenge remaining, got %d", len(remainingChallenges))
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
	app := createTestApp(t, dir)
	srv := &Server{
		app:      app,
		pbClient: pbclient.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
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
	app := createTestApp(t, dir)
	srv := &Server{
		app:      app,
		pbClient: pbclient.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
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
	// Disable rate limiting for this test to avoid 429 errors
	env.setRateLimit(0, 1000)
	pushTestChanges(t, env, 5)
	createTestSnapshot(t, env)
	verifySnapshotInPull(t, env)
	testCompaction(t, env)
}

func testCompaction(t *testing.T, env *serverTestEnv) {
	t.Helper()
	app := env.srv.app

	// Get the snapshot's min_seq (should be 5 after pushing 5 changes)
	snapshotsCol, err := app.FindCollectionByNameOrId("sync_snapshots")
	if err != nil {
		t.Fatalf("find snapshots collection: %v", err)
	}
	snapshots, err := app.FindRecordsByFilter(snapshotsCol, "user_id = {:user_id} && entity = {:entity}", "-min_seq", 1, 0,
		map[string]any{"user_id": env.userID, "entity": "todo"})
	if err != nil || len(snapshots) == 0 {
		t.Fatalf("query snapshot: %v", err)
	}
	snapshotMinSeq := int64(snapshots[0].GetInt("min_seq"))
	if snapshotMinSeq != 5 {
		t.Fatalf("expected snapshot min_seq=5, got %d", snapshotMinSeq)
	}

	// Push 3 more changes after snapshot (will be seq 6, 7, 8)
	pushTestChanges(t, env, 3)

	// Call compact endpoint
	client := vault.NewClient(vault.SyncConfig{BaseURL: env.server.URL, DeviceID: "device-a", AuthToken: env.token})
	if err := client.Compact(env.ctx, env.userID, "todo"); err != nil {
		t.Fatalf("compact failed: %v", err)
	}

	// Verify old changes (seq < 5) were deleted
	changesCol, err := app.FindCollectionByNameOrId("sync_changes")
	if err != nil {
		t.Fatalf("find changes collection: %v", err)
	}
	oldChanges, err := app.FindRecordsByFilter(changesCol, "user_id = {:user_id} && entity = {:entity} && seq < {:seq}", "", 100, 0,
		map[string]any{"user_id": env.userID, "entity": "todo", "seq": snapshotMinSeq})
	if err != nil {
		t.Fatalf("query old changes: %v", err)
	}
	if len(oldChanges) != 0 {
		t.Errorf("expected 0 old changes (seq < %d), got %d", snapshotMinSeq, len(oldChanges))
	}

	// Verify changes at boundary and newer (seq >= 5) still exist (5, 6, 7, 8 = 4 changes)
	newChanges, err := app.FindRecordsByFilter(changesCol, "user_id = {:user_id} && entity = {:entity} && seq >= {:seq}", "", 100, 0,
		map[string]any{"user_id": env.userID, "entity": "todo", "seq": snapshotMinSeq})
	if err != nil {
		t.Fatalf("query new changes: %v", err)
	}
	if len(newChanges) != 4 {
		t.Errorf("expected 4 changes (seq >= %d), got %d", snapshotMinSeq, len(newChanges))
	}
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

func TestAccountMigration(t *testing.T) {
	env := newServerTestEnv(t)
	env.pushChange(t, "device-a")

	newUserID := generateNewUserID(t)
	callMigrateEndpoint(t, env, newUserID)
	verifyDevicesMigrated(t, env, newUserID)
	verifyOldTokenInvalidated(t, env)
}

func TestRateLimiterWithZeroIntervalInServer(t *testing.T) {
	// Integration test: Verify that setting interval=0 in a real server
	// environment properly disables rate limiting
	env := newServerTestEnv(t)

	// Disable rate limiting
	env.setRateLimit(0, 1000)

	client := &http.Client{}

	// Make 100 rapid requests - all should succeed
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest("GET", env.server.URL+"/v1/sync/pull?user_id="+env.userID+"&since=0", nil)
		req.Header.Set("Authorization", "Bearer "+env.token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d (rate limiting should be disabled)", i, resp.StatusCode)
		}
	}
}

func TestCannotRevokeSelf(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	app := createTestApp(t, dir)
	srv := &Server{
		app:      app,
		pbClient: pbclient.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
	ts := startTestServer(t, srv)

	keys, _ := generateKeysAndSigner(t)
	userID := keys.UserID()

	// Register device A
	_, privA, _ := ed25519.GenerateKey(rand.Reader)
	signerA, _ := ssh.NewSignerFromKey(privA)
	tokenA := registerAndLogin(t, ts.URL, ctx, userID, signerA, "device-a")

	// Get device A's ID
	deviceAID := getFirstDeviceID(t, ts.URL, tokenA)

	// Try to revoke self - should fail
	client := &http.Client{}
	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/devices/"+deviceAID, nil)
	req.Header.Set("Authorization", "Bearer "+tokenA)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("revoke self request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 (cannot revoke self), got %d", resp.StatusCode)
	}

	// Verify token still works
	verifyTokenStatus(t, ts.URL, tokenA, userID, http.StatusOK)
}

func getFirstDeviceID(t *testing.T, baseURL, token string) string {
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
	if len(body.Devices) == 0 {
		t.Fatalf("expected at least 1 device, got 0")
	}
	return body.Devices[0].DeviceID
}

func TestSchemaAllowsEmptyDeviceID(t *testing.T) {
	dir := t.TempDir()
	app := createTestApp(t, dir)

	_ = &Server{
		app:      app,
		pbClient: pbclient.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}

	keys, _ := generateKeysAndSigner(t)
	userID := keys.UserID()

	tokensCol, err := app.FindCollectionByNameOrId("sync_tokens")
	if err != nil {
		t.Fatalf("find tokens collection: %v", err)
	}

	// Verify that empty string device_id works (for backward compatibility)
	tokenHash := hashToken("token_with_empty_device")
	now := time.Now().Add(12 * time.Hour).Unix()

	tokenRecord := core.NewRecord(tokensCol)
	tokenRecord.Set("token_hash", tokenHash)
	tokenRecord.Set("user_id", userID)
	tokenRecord.Set("device_id", "")
	tokenRecord.Set("expires_at", now)
	if err := app.Save(tokenRecord); err != nil {
		t.Fatalf("inserting token with empty string device_id should work: %v", err)
	}

	// Verify we can read it back
	foundToken, err := app.FindFirstRecordByFilter(tokensCol, "token_hash = {:token_hash}",
		map[string]any{"token_hash": tokenHash})
	if err != nil {
		t.Fatalf("query token: %v", err)
	}
	if foundToken.GetString("device_id") != "" {
		t.Fatalf("expected empty string device_id, got %q", foundToken.GetString("device_id"))
	}
}

func generateNewUserID(t *testing.T) string {
	t.Helper()
	newSeedParsed, _, err := vault.NewSeedPhrase()
	if err != nil {
		t.Fatalf("new seed: %v", err)
	}
	newKeys, err := vault.DeriveKeys(newSeedParsed, "", vault.DefaultKDFParams())
	if err != nil {
		t.Fatalf("derive new keys: %v", err)
	}
	return newKeys.UserID()
}

func callMigrateEndpoint(t *testing.T, env *serverTestEnv, newUserID string) {
	t.Helper()
	migrateReq := map[string]any{
		"old_user_id": env.userID,
		"new_user_id": newUserID,
		"confirm":     true,
	}
	body, err := json.Marshal(migrateReq)
	if err != nil {
		t.Fatalf("marshal migrate req: %v", err)
	}
	req, err := http.NewRequest("POST", env.server.URL+"/v1/account/migrate", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create migrate request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("migrate request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			t.Fatalf("expected 200, got %d: %v", resp.StatusCode, errResp)
		} else {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	}
}

func verifyDevicesMigrated(t *testing.T, env *serverTestEnv, newUserID string) {
	t.Helper()
	app := env.srv.app
	devicesCol, err := app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		t.Fatalf("find devices collection: %v", err)
	}
	devices, err := app.FindRecordsByFilter(devicesCol, "user_id = {:user_id}", "", 100, 0,
		map[string]any{"user_id": newUserID})
	if err != nil {
		t.Fatalf("query devices: %v", err)
	}
	if len(devices) == 0 {
		t.Fatalf("expected devices under new user_id")
	}
}

func verifyOldTokenInvalidated(t *testing.T, env *serverTestEnv) {
	t.Helper()
	client := &http.Client{}
	checkReq, _ := http.NewRequest("GET", env.server.URL+"/v1/sync/pull?user_id="+env.userID+"&since=0", nil)
	checkReq.Header.Set("Authorization", "Bearer "+env.token)
	checkResp, err := client.Do(checkReq)
	if err != nil {
		t.Fatalf("check old token request: %v", err)
	}
	if err := checkResp.Body.Close(); err != nil {
		t.Fatalf("close check response: %v", err)
	}
	if checkResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token should be invalidated, got %d", checkResp.StatusCode)
	}
}

func TestPerItemDeviceID(t *testing.T) {
	env := newServerTestEnv(t)
	deviceIDs := []string{"device-a", "device-b", "device-c"}

	pushItems := buildPerItemDeviceIDPushItems(t, env, deviceIDs)
	client := vault.NewClient(vault.SyncConfig{
		BaseURL:   env.server.URL,
		DeviceID:  "rotation-device",
		AuthToken: env.token,
	})

	// Push items with per-item device_ids
	pushResp, err := client.Push(env.ctx, env.userID, pushItems)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(pushResp.Ack) != len(pushItems) {
		t.Fatalf("expected %d acks, got %d", len(pushItems), len(pushResp.Ack))
	}

	// Pull and verify device_ids are preserved and decryption works
	pullResp, err := client.Pull(env.ctx, env.userID, 0)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(pullResp.Items) != len(deviceIDs) {
		t.Fatalf("expected %d items, got %d", len(deviceIDs), len(pullResp.Items))
	}

	verifyPulledItemsDeviceIDs(t, env, pullResp.Items, deviceIDs)
}

func buildPerItemDeviceIDPushItems(t *testing.T, env *serverTestEnv, deviceIDs []string) []vault.PushItem {
	t.Helper()
	pushItems := make([]vault.PushItem, 0, len(deviceIDs))
	for i, deviceID := range deviceIDs {
		change, err := vault.NewChange("doc", fmt.Sprintf("doc-%d", i+1), vault.OpUpsert, map[string]any{"text": "from " + deviceID})
		if err != nil {
			t.Fatalf("new change: %v", err)
		}

		changeBytes, err := json.Marshal(change)
		if err != nil {
			t.Fatalf("marshal change: %v", err)
		}

		aad := change.AAD(env.userID, deviceID)
		envelope, err := vault.Encrypt(env.keys.EncKey, changeBytes, aad)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		pushItems = append(pushItems, vault.PushItem{
			ChangeID: change.ChangeID,
			Entity:   change.Entity,
			TS:       change.TS.Unix(),
			Env:      envelope,
			DeviceID: deviceID,
		})
	}
	return pushItems
}

func verifyPulledItemsDeviceIDs(t *testing.T, env *serverTestEnv, items []vault.PullItem, deviceIDs []string) {
	t.Helper()
	for i, item := range items {
		if item.DeviceID != deviceIDs[i] {
			t.Errorf("item %d: expected device_id=%s, got %s", i, deviceIDs[i], item.DeviceID)
		}

		// Verify decryption works with the correct device_id in AAD
		aad := []byte("v1|" + env.userID + "|" + item.DeviceID + "|" + item.ChangeID + "|" + item.Entity)
		plaintext, err := vault.Decrypt(env.keys.EncKey, item.Env, aad)
		if err != nil {
			t.Errorf("decrypt item %d: %v", i, err)
			continue
		}

		var change vault.Change
		if err := json.Unmarshal(plaintext, &change); err != nil {
			t.Errorf("unmarshal change %d: %v", i, err)
		}
	}
}
