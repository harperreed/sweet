package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
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

	client := NewClient(SyncConfig{BaseURL: ts.URL, DeviceID: "dev-a", AuthToken: "test-token"})

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
	change, err := NewChange(entity, id, OpUpsert, payload)
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

	client := NewClient(SyncConfig{BaseURL: ts.URL, DeviceID: "rotation-device", AuthToken: "test-token"})

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
