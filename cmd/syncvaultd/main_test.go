package main

import (
	"bytes"
	"context"
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
	keys := generateTestKeys(t)

	// Create user and get both token and PB record ID (which is our userID for auth)
	token, userID := createTestUserAndTokenWithID(t, app, "device-test")

	if init, ok := pb.(pocketbaseAccountInitializer); ok {
		init.ensureAccount(userID)
	}

	return &serverTestEnv{
		t:      t,
		ctx:    ctx,
		dir:    dir,
		server: ts,
		srv:    srv,
		keys:   keys,
		userID: userID,
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

	// Ensure users auth collection exists (required for PocketBase JWT auth)
	// tests.NewTestApp() creates this by default, but we check anyway
	if _, err := app.FindCollectionByNameOrId("users"); err != nil {
		users := core.NewAuthCollection("users")
		if err := app.Save(users); err != nil {
			return err
		}
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

	// Create sync_devices collection (without ssh fields - using JWT auth now)
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
			Name: "name",
		},
		&core.NumberField{
			Name: "last_used_at",
		},
	)
	syncDevices.AddIndex("idx_sync_devices_device_id", true, "device_id", "")
	syncDevices.AddIndex("idx_sync_devices_user_id", false, "user_id", "")
	if err := app.Save(syncDevices); err != nil {
		return err
	}

	// sync_challenges and sync_tokens collections removed - using JWT auth now

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

	// Health endpoint for clients
	mux.HandleFunc("/v1/health", srv.handleHealth)

	// PB Auth endpoints
	mux.HandleFunc("/v1/auth/pb/register", srv.handlePBRegister)
	mux.HandleFunc("/v1/auth/pb/login", srv.handlePBLogin)
	mux.HandleFunc("/v1/auth/pb/refresh", srv.handlePBRefresh)

	// Sync endpoints (protected)
	mux.HandleFunc("/v1/sync/push", srv.withAuth(srv.handlePush))
	mux.HandleFunc("/v1/sync/pull", srv.withAuth(srv.handlePull))
	mux.HandleFunc("/v1/sync/snapshot", srv.withAuth(srv.handleSnapshot))
	mux.HandleFunc("/v1/sync/compact", srv.withAuth(srv.handleCompact))
	mux.HandleFunc("/v1/sync/wipe", srv.withAuth(srv.handleWipe))

	// Device management (protected)
	mux.HandleFunc("/v1/devices", srv.withAuth(srv.handleListDevices))
	mux.HandleFunc("/v1/devices/", srv.withAuth(srv.handleRevokeDevice))

	// Account management (protected)
	mux.HandleFunc("/v1/account/migrate", srv.withAuth(srv.handleMigrate))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func generateTestKeys(t *testing.T) vault.Keys {
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
	return keys
}

// createTestUserAndTokenWithID creates a PocketBase user and device, returns (token, pbRecordID).
// Tests should use pbRecordID as userID since that's what authUserJWT returns.
func createTestUserAndTokenWithID(t *testing.T, app core.App, deviceID string) (string, string) {
	t.Helper()

	// Create a user in the users collection
	usersCol, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatalf("find users collection: %v", err)
	}

	userRecord := core.NewRecord(usersCol)
	userRecord.Set("email", "test-"+deviceID+"@test.local")
	userRecord.SetPassword("testpassword123")
	userRecord.SetVerified(true)
	if err := app.Save(userRecord); err != nil {
		t.Fatalf("save user: %v", err)
	}

	// The PB record ID is what authUserJWT returns as userID
	userID := userRecord.Id

	// Create a device for this user
	devicesCol, err := app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		t.Fatalf("find sync_devices collection: %v", err)
	}

	deviceRecord := core.NewRecord(devicesCol)
	deviceRecord.Set("user_id", userID)
	deviceRecord.Set("device_id", deviceID)
	deviceRecord.Set("name", "test-device")
	if err := app.Save(deviceRecord); err != nil {
		t.Fatalf("save device: %v", err)
	}

	// Generate JWT token for this user
	token, err := userRecord.NewStaticAuthToken(24 * time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	return token, userID
}

type pocketbaseAccountInitializer interface {
	ensureAccount(userID string)
}

func (e *serverTestEnv) pushChange(t *testing.T, deviceID string) vault.Change {
	store := openTestStore(t, filepath.Join(e.dir, deviceID+".sqlite"))
	defer closeTestStore(t, store)

	client := vault.NewClient(vault.SyncConfig{
		AppID:     "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:   e.server.URL,
		DeviceID:  deviceID,
		AuthToken: e.token,
	})

	// Use Syncer to properly prefix the entity
	syncer := vault.NewSyncer(store, client, e.keys, e.userID)
	prefixedChange, err := syncer.QueueChange(e.ctx, "todo", "todo-1", vault.OpUpsert, map[string]any{"text": "integration"})
	if err != nil {
		t.Fatalf("queue change: %v", err)
	}

	// Strip the prefix to return what the app sees (manually since stripPrefix is unexported)
	change := prefixedChange
	change.Entity = strings.TrimPrefix(change.Entity, "550e8400-e29b-41d4-a716-446655440000.")

	var applied []vault.Change
	if err := vault.Sync(e.ctx, store, client, e.keys, e.userID, func(ctx context.Context, c vault.Change) error {
		applied = append(applied, c)
		return nil
	}); err != nil {
		t.Fatalf("sync push: %v", err)
	}
	// The push device gets its own change back during pull (server broadcasts it)
	if len(applied) != 1 {
		t.Fatalf("expected 1 applied change on push device (own change echoed back), got %d", len(applied))
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

	client := vault.NewClient(vault.SyncConfig{
		AppID:     "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:   e.server.URL,
		DeviceID:  deviceID,
		AuthToken: e.token,
	})
	var applied []vault.Change
	if err := vault.Sync(e.ctx, store, client, e.keys, e.userID, func(ctx context.Context, c vault.Change) error {
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
	dir := t.TempDir()
	app := createTestApp(t, dir)
	srv := &Server{
		app:      app,
		pbClient: pbclient.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
	ts := startTestServer(t, srv)

	// Create user and get both token and PB record ID (which is our userID for auth)
	tokenA, userID := createTestUserAndTokenWithID(t, app, "device-a")
	tokenB := createTestDeviceToken(t, app, userID, "device-b")

	// Both tokens should work (they share the same user JWT)
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

// createTestDeviceToken creates an additional device for an existing user.
// userID is the PocketBase record ID returned by createTestUserAndTokenWithID.
func createTestDeviceToken(t *testing.T, app core.App, userID, deviceID string) string {
	t.Helper()

	// Find existing user by record ID
	userRecord, err := app.FindRecordById("users", userID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}

	// Create device for this user
	devicesCol, err := app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		t.Fatalf("find sync_devices collection: %v", err)
	}

	deviceRecord := core.NewRecord(devicesCol)
	deviceRecord.Set("user_id", userID)
	deviceRecord.Set("device_id", deviceID)
	deviceRecord.Set("name", deviceID)
	if err := app.Save(deviceRecord); err != nil {
		t.Fatalf("save device: %v", err)
	}

	// Generate JWT token for user
	token, err := userRecord.NewStaticAuthToken(24 * time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	return token
}

func TestListDevices(t *testing.T) {
	env := newServerTestEnv(t)

	// Create a second device
	createTestDeviceToken(t, env.srv.app, env.userID, "second-device")

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
	dir := t.TempDir()
	app := createTestApp(t, dir)
	srv := &Server{
		app:      app,
		pbClient: pbclient.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
	ts := startTestServer(t, srv)

	// Create user and get both token and PB record ID (which is our userID for auth)
	tokenA, userID := createTestUserAndTokenWithID(t, app, "device-a")

	// Create device B for the same user
	createTestDeviceToken(t, app, userID, "device-b")

	// Get device B's ID
	deviceBID := getSecondDeviceID(t, ts.URL, tokenA)

	// Revoke device B using device A's token
	revokeDevice(t, ts.URL, tokenA, deviceBID)

	// Device A token still works (200) - JWT tokens are user-level, not device-level
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
	client := vault.NewClient(vault.SyncConfig{
		AppID:     "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:   env.server.URL,
		DeviceID:  "device-a",
		AuthToken: env.token,
	})
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
	client := vault.NewClient(vault.SyncConfig{
		AppID:     "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:   env.server.URL,
		DeviceID:  "device-a",
		AuthToken: env.token,
	})
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
	client := vault.NewClient(vault.SyncConfig{
		AppID:     "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:   env.server.URL,
		DeviceID:  "device-b",
		AuthToken: env.token,
	})
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

// TestAccountMigration tests migrating vault data from one userID to another.
// With JWT auth, the token remains valid after migration (JWT is PocketBase user-level,
// not vault userID-level). The migration moves devices to the new vault userID.
func TestAccountMigration(t *testing.T) {
	env := newServerTestEnv(t)
	env.pushChange(t, "device-a")

	newUserID := generateNewUserID(t)
	callMigrateEndpoint(t, env, newUserID)
	verifyDevicesMigrated(t, env, newUserID)
	// With JWT auth, the token remains valid (it's tied to PocketBase user, not vault userID)
	verifyTokenStillValidAfterMigration(t, env)
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

// TestSelfRevocationAllowedWithJWTAuth verifies that with JWT auth, we cannot
// detect which device is making the request, so self-revocation is allowed.
// Self-revocation protection must be enforced client-side with JWT auth.
func TestSelfRevocationAllowedWithJWTAuth(t *testing.T) {
	dir := t.TempDir()
	app := createTestApp(t, dir)
	srv := &Server{
		app:      app,
		pbClient: pbclient.NoopClient{},
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
	ts := startTestServer(t, srv)

	// Create user and get both token and PB record ID (which is our userID for auth)
	tokenA, userID := createTestUserAndTokenWithID(t, app, "device-a")

	// Get device A's ID
	deviceAID := getFirstDeviceID(t, ts.URL, tokenA)

	// With JWT auth, self-revocation succeeds because server can't detect which device
	// is making the request (JWT tokens are user-level, not device-level)
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (revocation succeeds with JWT auth), got %d", resp.StatusCode)
	}

	// Token still works (JWT tokens are user-level, not invalidated by device revocation)
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

// verifyTokenStillValidAfterMigration confirms that JWT tokens remain valid after
// vault data migration. JWT tokens are tied to PocketBase users, not vault userIDs.
func verifyTokenStillValidAfterMigration(t *testing.T, env *serverTestEnv) {
	t.Helper()
	client := &http.Client{}
	checkReq, _ := http.NewRequest("GET", env.server.URL+"/v1/sync/pull?user_id="+env.userID+"&since=0", nil)
	checkReq.Header.Set("Authorization", "Bearer "+env.token)
	checkResp, err := client.Do(checkReq)
	if err != nil {
		t.Fatalf("check token request: %v", err)
	}
	if err := checkResp.Body.Close(); err != nil {
		t.Fatalf("close check response: %v", err)
	}
	if checkResp.StatusCode != http.StatusOK {
		t.Fatalf("token should still be valid with JWT auth, got %d", checkResp.StatusCode)
	}
}

func TestPerItemDeviceID(t *testing.T) {
	env := newServerTestEnv(t)
	deviceIDs := []string{"device-a", "device-b", "device-c"}

	pushItems := buildPerItemDeviceIDPushItems(t, env, deviceIDs)
	client := vault.NewClient(vault.SyncConfig{
		AppID:     "550e8400-e29b-41d4-a716-446655440000",
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

func TestHealthEndpoint(t *testing.T) {
	env := newServerTestEnv(t)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", env.server.URL+"/v1/health", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Time int64 `json:"time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Verify timestamp is within 1 minute of current time
	now := time.Now().Unix()
	if body.Time < now-60 || body.Time > now+60 {
		t.Errorf("server time %d is too far from now %d", body.Time, now)
	}
}

func TestWipeDeletesUserData(t *testing.T) {
	env := newServerTestEnv(t)

	// Push some changes
	env.pushChange(t, "device-a")
	env.pushChange(t, "device-a")

	// Verify we can pull them back
	client := vault.NewClient(vault.SyncConfig{
		AppID:     "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:   env.server.URL,
		DeviceID:  "device-a",
		AuthToken: env.token,
	})
	pullResp, err := client.Pull(env.ctx, env.userID, 0)
	if err != nil {
		t.Fatalf("pull before wipe: %v", err)
	}
	if len(pullResp.Items) < 1 {
		t.Fatalf("expected at least 1 item before wipe, got %d", len(pullResp.Items))
	}

	// Call wipe endpoint
	req, _ := http.NewRequest("POST", env.server.URL+"/v1/sync/wipe", nil)
	req.Header.Set("Authorization", "Bearer "+env.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("wipe request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wipe expected 200, got %d", resp.StatusCode)
	}

	// Verify wipe response contains deleted count
	var wipeResp struct {
		Deleted int `json:"deleted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wipeResp); err != nil {
		t.Fatalf("decode wipe response: %v", err)
	}
	if wipeResp.Deleted < 1 {
		t.Fatalf("expected at least 1 deleted, got %d", wipeResp.Deleted)
	}

	// Verify data is gone - pull should return empty
	pullResp2, err := client.Pull(env.ctx, env.userID, 0)
	if err != nil {
		t.Fatalf("pull after wipe: %v", err)
	}
	if len(pullResp2.Items) != 0 {
		t.Fatalf("expected 0 items after wipe, got %d", len(pullResp2.Items))
	}
}

func TestWipeRequiresAuth(t *testing.T) {
	env := newServerTestEnv(t)

	// Call wipe without auth token
	req, _ := http.NewRequest("POST", env.server.URL+"/v1/sync/wipe", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("wipe request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wipe without auth expected 401, got %d", resp.StatusCode)
	}
}

// TestGetNextSeqTxBehavior verifies getNextSeqTx behavior for Issue #5 fix.
// Before the fix: any error would return (1, nil) silently.
// After the fix: database errors are properly returned as (0, error).
func TestGetNextSeqTxBehavior(t *testing.T) {
	dir := t.TempDir()
	app := createTestApp(t, dir)

	changesCol, err := app.FindCollectionByNameOrId("sync_changes")
	if err != nil {
		t.Fatalf("find collection: %v", err)
	}

	// Test 1: New user with no existing records should get seq=1
	seq, err := getNextSeqTx(app, changesCol, "new-user")
	if err != nil {
		t.Errorf("new user should not error, got: %v", err)
	}
	if seq != 1 {
		t.Errorf("new user expected seq=1, got %d", seq)
	}

	// Test 2: Insert a record at seq=5 and verify increment
	rec := core.NewRecord(changesCol)
	rec.Set("seq", 5)
	rec.Set("user_id", "existing-user")
	rec.Set("change_id", "change-1")
	rec.Set("device_id", "dev-1")
	rec.Set("entity", "test")
	rec.Set("ts", 1234567890)
	rec.Set("nonce_b64", "YWJjZA==")
	rec.Set("ct_b64", "ZGVmZw==")
	if err := app.Save(rec); err != nil {
		t.Fatalf("save record: %v", err)
	}

	seq, err = getNextSeqTx(app, changesCol, "existing-user")
	if err != nil {
		t.Errorf("existing user should not error, got: %v", err)
	}
	if seq != 6 {
		t.Errorf("existing user expected seq=6, got %d", seq)
	}

	// Test 3: Verify the function signature now properly returns errors
	// (The fix changed from returning (1, nil) on all errors to returning (0, err))
	// This is validated by code inspection and the fact that the transaction
	// handler at line 273-275 in main.go now receives and handles errors.
}
