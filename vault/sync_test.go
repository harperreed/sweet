package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSyncPushAndPull(t *testing.T) {
	env := newSyncTestEnv(t)
	env.enqueueLocalChange(t, "todo", "id1", map[string]any{"text": "local"})
	env.syncExpectPush(t)
	env.prepareRemoteChange(t, "todo", "remote-id", map[string]any{"text": "remote"})
	env.syncExpectPull(t)

	if env.lastApplied == nil || env.lastApplied.EntityID != "remote-id" {
		t.Fatalf("expected remote-id applied, got %+v", env.lastApplied)
	}
	if seq, err := env.store.GetState(env.ctx, "last_pulled_seq", ""); err != nil || seq != "1" {
		t.Fatalf("expected seq=1, got %q err=%v", seq, err)
	}
}

type syncTestEnv struct {
	t           *testing.T
	ctx         context.Context
	store       *Store
	keys        Keys
	device      string
	userID      string // Server-side user identifier
	fake        *fakeSyncServer
	server      *httptest.Server
	client      *Client
	lastApplied *Change
}

func newSyncTestEnv(t *testing.T) *syncTestEnv {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("close store: %v", cerr)
		}
	})

	seed := SeedPhrase{Raw: bytes32(0x42)}
	params := DefaultKDFParams()
	params.Time = 1
	params.MemoryMB = 32
	keys, err := DeriveKeys(seed, "", params)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	fake := newFakeSyncServer()
	ts := httptest.NewServer(fake.handler())
	t.Cleanup(ts.Close)

	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      ts.URL,
		DeviceID:     "dev-a",
		AuthToken:    "test-token",
		TokenExpires: time.Now().Add(1 * time.Hour),
	})

	return &syncTestEnv{
		t:      t,
		ctx:    ctx,
		store:  store,
		keys:   keys,
		device: "dev-a",
		userID: keys.UserID(), // In tests with fake server, vault-derived ID is fine
		fake:   fake,
		server: ts,
		client: client,
	}
}

func (e *syncTestEnv) enqueueLocalChange(t *testing.T, entity, id string, payload map[string]any) Change {
	change, err := NewChange(entity, id, OpUpsert, payload)
	if err != nil {
		t.Fatalf("new change: %v", err)
	}
	plain, err := json.Marshal(change)
	if err != nil {
		t.Fatalf("marshal change: %v", err)
	}
	env, err := Encrypt(e.keys.EncKey, plain, change.AAD(e.keys.UserID(), e.device))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := e.store.EnqueueEncryptedChange(e.ctx, change, e.keys.UserID(), e.device, env); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return change
}

func (e *syncTestEnv) syncExpectPush(t *testing.T) {
	var applied []Change
	if err := Sync(e.ctx, e.store, e.client, e.keys, e.userID, func(ctx context.Context, c Change) error {
		applied = append(applied, c)
		return nil
	}); err != nil {
		t.Fatalf("sync push: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("expected no pulls, got %d", len(applied))
	}
	if e.fake.pushedCount() != 1 {
		t.Fatalf("expected 1 pushed change, got %d", e.fake.pushedCount())
	}
	items, err := e.store.DequeueBatch(e.ctx, 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("outbox should be empty, got %d", len(items))
	}
}

func (e *syncTestEnv) prepareRemoteChange(t *testing.T, entity, id string, payload map[string]any) {
	// Prefix entity with AppID for namespace isolation
	prefixedEntity := e.client.prefixedEntity(entity)
	change, err := NewChange(prefixedEntity, id, OpUpsert, payload)
	if err != nil {
		t.Fatalf("remote change: %v", err)
	}
	plain, err := json.Marshal(change)
	if err != nil {
		t.Fatalf("marshal remote: %v", err)
	}
	remoteDevice := "dev-b"
	env, err := Encrypt(e.keys.EncKey, plain, change.AAD(e.keys.UserID(), remoteDevice))
	if err != nil {
		t.Fatalf("encrypt remote: %v", err)
	}
	e.fake.setPull([]PullItem{{
		Seq:      1,
		ChangeID: change.ChangeID,
		DeviceID: remoteDevice,
		Entity:   change.Entity,
		Env:      env,
	}})
}

func (e *syncTestEnv) syncExpectPull(t *testing.T) {
	var applied []Change
	if err := Sync(e.ctx, e.store, e.client, e.keys, e.userID, func(ctx context.Context, c Change) error {
		applied = append(applied, c)
		return nil
	}); err != nil {
		t.Fatalf("sync pull: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("expected 1 applied change, got %d", len(applied))
	}
	e.lastApplied = &applied[0]
}

type fakeSyncServer struct {
	mu        sync.Mutex
	pushed    []PushItem
	pullItems []PullItem
}

func newFakeSyncServer() *fakeSyncServer { return &fakeSyncServer{} }

func (s *fakeSyncServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sync/push", s.handlePush)
	mux.HandleFunc("/v1/sync/pull", s.handlePull)
	return mux
}

func (s *fakeSyncServer) handlePush(w http.ResponseWriter, r *http.Request) {
	var req PushReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.pushed = append(s.pushed, req.Changes...)
	s.mu.Unlock()

	ack := make([]string, 0, len(req.Changes))
	for _, ch := range req.Changes {
		ack = append(ack, ch.ChangeID)
	}
	if err := json.NewEncoder(w).Encode(PushResp{Ack: ack}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *fakeSyncServer) handlePull(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	items := make([]PullItem, len(s.pullItems))
	copy(items, s.pullItems)
	s.pullItems = nil
	s.mu.Unlock()
	if err := json.NewEncoder(w).Encode(PullResp{Items: items}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *fakeSyncServer) pushedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pushed)
}

func (s *fakeSyncServer) setPull(items []PullItem) {
	s.mu.Lock()
	s.pullItems = append([]PullItem(nil), items...)
	s.mu.Unlock()
}

func TestPushItemPreservesPerItemDeviceID(t *testing.T) {
	ctx := context.Background()
	keys := testDeriveKeys(t)

	fake := newFakeSyncServer()
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      ts.URL,
		DeviceID:     "rotation-device",
		AuthToken:    "test-token",
		TokenExpires: time.Now().Add(1 * time.Hour),
	})

	// Create changes that were originally from different devices
	deviceIDs := []string{"device-a", "device-b", "device-c"}
	pushItems := buildPushItemsWithDeviceIDs(t, keys, deviceIDs)

	// Push items with per-item device_ids
	resp, err := client.Push(ctx, keys.UserID(), pushItems)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(resp.Ack) != len(pushItems) {
		t.Fatalf("expected %d acks, got %d", len(pushItems), len(resp.Ack))
	}

	// Verify that fake server received the per-item device_ids
	fake.mu.Lock()
	pushedItems := fake.pushed
	fake.mu.Unlock()

	if len(pushedItems) != len(deviceIDs) {
		t.Fatalf("expected %d pushed items, got %d", len(deviceIDs), len(pushedItems))
	}

	for i, item := range pushedItems {
		if item.DeviceID != deviceIDs[i] {
			t.Errorf("item %d: expected device_id=%s, got %s", i, deviceIDs[i], item.DeviceID)
		}
	}
}

func testDeriveKeys(t *testing.T) Keys {
	t.Helper()
	seed := SeedPhrase{Raw: bytes32(0x42)}
	params := DefaultKDFParams()
	params.Time = 1
	params.MemoryMB = 32
	keys, err := DeriveKeys(seed, "", params)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	return keys
}

func buildPushItemsWithDeviceIDs(t *testing.T, keys Keys, deviceIDs []string) []PushItem {
	t.Helper()
	pushItems := make([]PushItem, 0, len(deviceIDs))
	for i, deviceID := range deviceIDs {
		change, err := NewChange("doc", fmt.Sprintf("doc-%d", i+1), OpUpsert, map[string]any{"text": "from " + deviceID})
		if err != nil {
			t.Fatalf("new change: %v", err)
		}

		plain, err := json.Marshal(change)
		if err != nil {
			t.Fatalf("marshal change: %v", err)
		}

		aad := change.AAD(keys.UserID(), deviceID)
		env, err := Encrypt(keys.EncKey, plain, aad)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		pushItems = append(pushItems, PushItem{
			ChangeID: change.ChangeID,
			Entity:   change.Entity,
			TS:       change.TS.Unix(),
			Env:      env,
			DeviceID: deviceID,
		})
	}
	return pushItems
}

func TestSyncEvents(t *testing.T) {
	env := newSyncTestEnv(t)

	// Track events
	var started, completed bool
	var pushedTotal, pulledTotal int

	events := &SyncEvents{
		OnStart: func() {
			started = true
		},
		OnPush: func(pushed, remaining int) {
			pushedTotal += pushed
		},
		OnPull: func(pulled int) {
			pulledTotal = pulled
		},
		OnComplete: func(pushed, pulled int) {
			completed = true
		},
	}

	// Enqueue a local change
	env.enqueueLocalChange(t, "test", "1", map[string]any{"x": 1})

	// Prepare a remote change
	env.prepareRemoteChange(t, "test", "2", map[string]any{"y": 2})

	// Sync with events
	err := Sync(env.ctx, env.store, env.client, env.keys, env.userID, func(ctx context.Context, c Change) error {
		return nil
	}, events)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	if !started {
		t.Error("OnStart was not called")
	}
	if !completed {
		t.Error("OnComplete was not called")
	}
	if pushedTotal != 1 {
		t.Errorf("expected 1 pushed, got %d", pushedTotal)
	}
	if pulledTotal != 1 {
		t.Errorf("expected 1 pulled, got %d", pulledTotal)
	}
}

func TestSyncEvents_NilEvents(t *testing.T) {
	env := newSyncTestEnv(t)

	// Should work with nil events
	err := Sync(env.ctx, env.store, env.client, env.keys, env.userID, func(ctx context.Context, c Change) error {
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("sync with nil events: %v", err)
	}
}

func TestSyncerPushFlowPrefixesEntities(t *testing.T) {
	env := newSyncTestEnv(t)

	// Create syncer
	syncer := NewSyncer(env.store, env.client, env.keys, env.userID, nil)

	// Queue changes using syncer (entities will be prefixed)
	_, err := syncer.QueueChange(env.ctx, "todo", "task-1", OpUpsert, map[string]any{"text": "prefixed"})
	if err != nil {
		t.Fatalf("queue change: %v", err)
	}

	// Sync should push the change
	applied := []Change{}
	err = Sync(env.ctx, env.store, env.client, env.keys, env.userID, func(ctx context.Context, c Change) error {
		applied = append(applied, c)
		return nil
	})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Verify the change was pushed
	if env.fake.pushedCount() != 1 {
		t.Fatalf("expected 1 pushed, got %d", env.fake.pushedCount())
	}

	// Verify the pushed entity includes the prefix
	env.fake.mu.Lock()
	pushedEntity := env.fake.pushed[0].Entity
	env.fake.mu.Unlock()

	expectedEntity := "550e8400-e29b-41d4-a716-446655440000.todo"
	if pushedEntity != expectedEntity {
		t.Errorf("expected pushed entity=%q, got %q", expectedEntity, pushedEntity)
	}
}

func TestPullFlowFiltersAndStripsPrefix(t *testing.T) {
	env := newSyncTestEnv(t)
	ourAppID := "550e8400-e29b-41d4-a716-446655440000"
	otherAppID := "660e8400-e29b-41d4-a716-446655440000"

	// Prepare remote changes:
	// 1. Our app's change (should be applied with prefix stripped)
	ourChange, err := NewChange(ourAppID+".todo", "our-task", OpUpsert, map[string]any{"text": "ours"})
	if err != nil {
		t.Fatalf("our change: %v", err)
	}
	ourPlain, _ := json.Marshal(ourChange)
	ourEnv, _ := Encrypt(env.keys.EncKey, ourPlain, ourChange.AAD(env.userID, "dev-b"))

	// 2. Other app's change (should be skipped)
	otherChange, err := NewChange(otherAppID+".todo", "other-task", OpUpsert, map[string]any{"text": "theirs"})
	if err != nil {
		t.Fatalf("other change: %v", err)
	}
	otherPlain, _ := json.Marshal(otherChange)
	otherEnv, _ := Encrypt(env.keys.EncKey, otherPlain, otherChange.AAD(env.userID, "dev-c"))

	// 3. Unprefixed change (should be skipped)
	unprefixedChange, err := NewChange("legacy", "old-task", OpUpsert, map[string]any{"text": "legacy"})
	if err != nil {
		t.Fatalf("unprefixed change: %v", err)
	}
	unprefixedPlain, _ := json.Marshal(unprefixedChange)
	unprefixedEnv, _ := Encrypt(env.keys.EncKey, unprefixedPlain, unprefixedChange.AAD(env.userID, "dev-d"))

	// Set all three items in pull response
	env.fake.setPull([]PullItem{
		{Seq: 1, ChangeID: ourChange.ChangeID, DeviceID: "dev-b", Entity: ourChange.Entity, Env: ourEnv},
		{Seq: 2, ChangeID: otherChange.ChangeID, DeviceID: "dev-c", Entity: otherChange.Entity, Env: otherEnv},
		{Seq: 3, ChangeID: unprefixedChange.ChangeID, DeviceID: "dev-d", Entity: unprefixedChange.Entity, Env: unprefixedEnv},
	})

	// Sync and collect applied changes
	applied := []Change{}
	err = Sync(env.ctx, env.store, env.client, env.keys, env.userID, func(ctx context.Context, c Change) error {
		applied = append(applied, c)
		return nil
	})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Verify only our app's change was applied
	if len(applied) != 1 {
		t.Fatalf("expected 1 applied change, got %d", len(applied))
	}

	// Verify the entity prefix was stripped
	if applied[0].Entity != "todo" {
		t.Errorf("expected entity=todo (prefix stripped), got %q", applied[0].Entity)
	}
	if applied[0].EntityID != "our-task" {
		t.Errorf("expected entityID=our-task, got %q", applied[0].EntityID)
	}

	// Verify last_pulled_seq was updated to highest seq (3), even though we skipped items
	seq, err := env.store.GetState(env.ctx, "last_pulled_seq", "")
	if err != nil {
		t.Fatalf("get last_pulled_seq: %v", err)
	}
	if seq != "3" {
		t.Errorf("expected last_pulled_seq=3, got %q", seq)
	}
}

func TestPullFlowStripsPrefix(t *testing.T) {
	env := newSyncTestEnv(t)
	appID := "550e8400-e29b-41d4-a716-446655440000"

	// Prepare remote change with prefixed entity
	prefixedEntity := appID + ".item"
	change, err := NewChange(prefixedEntity, "item-1", OpUpsert, map[string]any{"data": "test"})
	if err != nil {
		t.Fatalf("new change: %v", err)
	}
	plain, _ := json.Marshal(change)
	remoteDevice := "dev-b"
	envelope, _ := Encrypt(env.keys.EncKey, plain, change.AAD(env.userID, remoteDevice))

	env.fake.setPull([]PullItem{{
		Seq:      1,
		ChangeID: change.ChangeID,
		DeviceID: remoteDevice,
		Entity:   change.Entity,
		Env:      envelope,
	}})

	// Sync and capture applied change
	var appliedEntity string
	err = Sync(env.ctx, env.store, env.client, env.keys, env.userID, func(ctx context.Context, c Change) error {
		appliedEntity = c.Entity
		return nil
	})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Verify prefix was stripped
	if appliedEntity != "item" {
		t.Errorf("expected entity=item (prefix stripped), got %q", appliedEntity)
	}
}

func TestSyncRefreshesTokenAutomatically(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	keys := testDeriveKeys(t)

	// Create fake server that handles both sync and auth endpoints
	var tokenRefreshed bool
	fake := newFakeSyncServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sync/push", fake.handlePush)
	mux.HandleFunc("/v1/sync/pull", fake.handlePull)
	mux.HandleFunc("/v1/auth/pb/refresh", func(w http.ResponseWriter, r *http.Request) {
		tokenRefreshed = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token":         "new-token",
			"refresh_token": "new-refresh-token",
			"expires_unix":  time.Now().Add(1 * time.Hour).Unix(),
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Create client with expired token but valid refresh token
	var callbackCalled bool
	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      ts.URL,
		DeviceID:     "dev-a",
		AuthToken:    "expired-token",
		RefreshToken: "refresh-token",
		TokenExpires: time.Now().Add(-1 * time.Hour), // expired
		OnTokenRefresh: func(token, refresh string, expires time.Time) {
			callbackCalled = true
		},
	})

	// Sync should automatically refresh the token
	err = Sync(ctx, store, client, keys, keys.UserID(), func(ctx context.Context, c Change) error {
		return nil
	})
	if err != nil {
		t.Fatalf("sync should succeed after token refresh: %v", err)
	}

	if !tokenRefreshed {
		t.Error("expected token to be refreshed")
	}
	if !callbackCalled {
		t.Error("expected OnTokenRefresh callback to be called")
	}
}

func TestSyncFailsWhenTokenExpiredWithoutRefresh(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	keys := testDeriveKeys(t)

	fake := newFakeSyncServer()
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	// Create client with expired token and NO refresh token
	client := NewClient(SyncConfig{
		AppID:        "550e8400-e29b-41d4-a716-446655440000",
		BaseURL:      ts.URL,
		DeviceID:     "dev-a",
		AuthToken:    "expired-token",
		RefreshToken: "",                             // no refresh token
		TokenExpires: time.Now().Add(-1 * time.Hour), // expired
	})

	// Sync should fail with ErrTokenExpired
	err = Sync(ctx, store, client, keys, keys.UserID(), func(ctx context.Context, c Change) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error when token expired without refresh token")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}
