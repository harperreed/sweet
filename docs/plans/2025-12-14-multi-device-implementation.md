# Multi-Device Sync v2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enhance suite-sync to properly support single-user, multi-device sync with conflict detection, rate limiting, snapshots, and seed rotation.

**Architecture:** Six incremental features building on existing vault library and syncvaultd server. Each feature is independently testable. Server changes are backward-compatible.

**Tech Stack:** Go 1.22+, SQLite (modernc.org/sqlite), XChaCha20-Poly1305, golang.org/x/time/rate

---

## Task 1: Background Cleanup

**Files:**
- Modify: `cmd/syncvaultd/main.go:56-64`
- Create: `cmd/syncvaultd/cleanup.go`
- Modify: `cmd/syncvaultd/main_test.go` (add test)

### Step 1: Write the failing test

Add to `cmd/syncvaultd/main_test.go`:

```go
func TestCleanupPurgesExpiredTokensAndChallenges(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "test.sqlite"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	srv := &Server{db: db, pbClient: pocketbase.NoopClient{}}
	if err := srv.migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Now().Unix()
	expired := now - 3600 // 1 hour ago
	valid := now + 3600   // 1 hour from now

	// Insert expired and valid tokens
	db.Exec(`INSERT INTO tokens(token_hash, user_id, expires_at) VALUES('expired1', 'user1', ?)`, expired)
	db.Exec(`INSERT INTO tokens(token_hash, user_id, expires_at) VALUES('valid1', 'user1', ?)`, valid)

	// Insert expired and valid challenges
	db.Exec(`INSERT INTO challenges(challenge_id, user_id, challenge, expires_at) VALUES('ch-expired', 'user1', X'00', ?)`, expired)
	db.Exec(`INSERT INTO challenges(challenge_id, user_id, challenge, expires_at) VALUES('ch-valid', 'user1', X'00', ?)`, valid)

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
	db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 token remaining, got %d", count)
	}
	db.QueryRow(`SELECT COUNT(*) FROM challenges`).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 challenge remaining, got %d", count)
	}
}
```

### Step 2: Run test to verify it fails

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestCleanupPurgesExpiredTokensAndChallenges`
Expected: FAIL with "srv.cleanupExpired undefined"

### Step 3: Write minimal implementation

Create `cmd/syncvaultd/cleanup.go`:

```go
// ABOUTME: Background cleanup routines for expired tokens and challenges.
// ABOUTME: Prevents unbounded growth of auth-related tables.

package main

import (
	"context"
	"log"
	"time"
)

// CleanupStats tracks how many records were purged.
type CleanupStats struct {
	tokens     int64
	challenges int64
}

// cleanupExpired deletes expired tokens and challenges, returning counts.
func (s *Server) cleanupExpired(ctx context.Context) CleanupStats {
	now := time.Now().Unix()
	var stats CleanupStats

	res, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE expires_at < ?`, now)
	if err != nil {
		log.Printf("cleanup tokens error: %v", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		stats.tokens = n
	}

	res, err = s.db.ExecContext(ctx, `DELETE FROM challenges WHERE expires_at < ?`, now)
	if err != nil {
		log.Printf("cleanup challenges error: %v", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		stats.challenges = n
	}

	return stats
}

// startCleanupRoutine runs cleanup every hour in background.
func (s *Server) startCleanupRoutine(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := s.cleanupExpired(ctx)
				if stats.tokens > 0 || stats.challenges > 0 {
					log.Printf("cleanup: purged %d tokens, %d challenges", stats.tokens, stats.challenges)
				}
			}
		}
	}()
}
```

### Step 4: Run test to verify it passes

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestCleanupPurgesExpiredTokensAndChallenges`
Expected: PASS

### Step 5: Wire up in main()

Modify `cmd/syncvaultd/main.go`. After `srv.migrate()` call (~line 54), add:

```go
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.startCleanupRoutine(ctx)
```

### Step 6: Run all server tests

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/...`
Expected: All tests PASS

### Step 7: Commit

```bash
git add cmd/syncvaultd/cleanup.go cmd/syncvaultd/main.go cmd/syncvaultd/main_test.go
git commit -m "feat(server): add background cleanup for expired tokens/challenges"
```

---

## Task 2: Rate Limiting

**Files:**
- Modify: `cmd/syncvaultd/main.go` (add limiter field, modify withAuth)
- Create: `cmd/syncvaultd/ratelimit.go`
- Modify: `cmd/syncvaultd/main_test.go` (add test)
- Modify: `go.mod` (add golang.org/x/time)

### Step 1: Add dependency

Run: `cd /Users/harper/Public/src/2389/suite-sync && go get golang.org/x/time/rate`

### Step 2: Write the failing test

Add to `cmd/syncvaultd/main_test.go`:

```go
func TestRateLimitRejects429(t *testing.T) {
	env := newServerTestEnv(t)

	// Configure tight rate limit for testing: 2 requests, no burst
	env.setRateLimit(rate.Every(time.Second), 1)

	client := &http.Client{}

	// First request should succeed
	req1, _ := http.NewRequest("GET", env.server.URL+"/v1/sync/pull?user_id="+env.userID+"&since=0", nil)
	req1.Header.Set("Authorization", "Bearer "+env.token)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp1.Body.Close()
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
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request expected 429, got %d", resp2.StatusCode)
	}
}
```

### Step 3: Run test to verify it fails

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestRateLimitRejects429`
Expected: FAIL (method setRateLimit undefined, or 200 instead of 429)

### Step 4: Write rate limit implementation

Create `cmd/syncvaultd/ratelimit.go`:

```go
// ABOUTME: Per-user rate limiting using token bucket algorithm.
// ABOUTME: Protects server from runaway clients and abuse.

package main

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitConfig holds rate limiter settings.
type RateLimitConfig struct {
	Interval time.Duration // Time between allowed requests
	Burst    int           // Max burst size
}

// DefaultRateLimitConfig returns ~100 req/min with burst of 10.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Interval: 600 * time.Millisecond,
		Burst:    10,
	}
}

// rateLimiterStore manages per-user rate limiters.
type rateLimiterStore struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	config   RateLimitConfig
}

func newRateLimiterStore(config RateLimitConfig) *rateLimiterStore {
	return &rateLimiterStore{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

func (s *rateLimiterStore) get(userID string) *rate.Limiter {
	s.mu.RLock()
	limiter, ok := s.limiters[userID]
	s.mu.RUnlock()
	if ok {
		return limiter
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check after acquiring write lock
	if limiter, ok := s.limiters[userID]; ok {
		return limiter
	}
	limiter = rate.NewLimiter(rate.Every(s.config.Interval), s.config.Burst)
	s.limiters[userID] = limiter
	return limiter
}

func (s *rateLimiterStore) setConfig(interval time.Duration, burst int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = RateLimitConfig{Interval: interval, Burst: burst}
	// Clear existing limiters so they pick up new config
	s.limiters = make(map[string]*rate.Limiter)
}
```

### Step 5: Modify Server struct and withAuth

In `cmd/syncvaultd/main.go`, update the Server struct and initialization:

```go
// Server bundles state for syncvaultd handlers.
type Server struct {
	db       *sql.DB
	pbClient pocketbase.Client
	limiters *rateLimiterStore
}
```

In `main()`, after creating srv:

```go
	srv := &Server{
		db:       db,
		pbClient: pbClient,
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
```

Update `withAuth` function:

```go
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := s.authUser(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, err.Error())
			return
		}

		// Rate limit check
		if s.limiters != nil {
			limiter := s.limiters.get(userID)
			if !limiter.Allow() {
				fail(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}

		ctx := context.WithValue(r.Context(), ctxUserIDKey{}, userID)
		next(w, r.WithContext(ctx))
	}
}
```

### Step 6: Add test helper method

Add to `cmd/syncvaultd/main_test.go`:

```go
func (e *serverTestEnv) setRateLimit(interval time.Duration, burst int) {
	// Access the server's limiters through the test server
	// We need to modify newServerTestEnvWithPB to expose the server
}
```

Actually, we need to modify the test setup. Update `serverTestEnv` struct:

```go
type serverTestEnv struct {
	t      *testing.T
	ctx    context.Context
	dir    string
	server *httptest.Server
	srv    *Server // Add this field
	keys   vault.Keys
	userID string
	token  string
}
```

Update `newServerTestEnvWithPB`:

```go
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
		srv:    srv, // Store server reference
		keys:   keys,
		userID: keys.UserID(),
		token:  token,
	}
}
```

Add helper method:

```go
func (e *serverTestEnv) setRateLimit(interval time.Duration, burst int) {
	e.srv.limiters.setConfig(interval, burst)
}
```

Add import for `"golang.org/x/time/rate"` at top of test file.

### Step 7: Run test to verify it passes

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestRateLimitRejects429`
Expected: PASS

### Step 8: Run all server tests

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/...`
Expected: All tests PASS

### Step 9: Commit

```bash
git add cmd/syncvaultd/ratelimit.go cmd/syncvaultd/main.go cmd/syncvaultd/main_test.go go.mod go.sum
git commit -m "feat(server): add per-user rate limiting"
```

---

## Task 3: Multi-Device Authentication

**Files:**
- Modify: `cmd/syncvaultd/main.go` (schema, register, auth)
- Create: `cmd/syncvaultd/devices.go` (list/revoke endpoints)
- Modify: `cmd/syncvaultd/main_test.go` (add tests)

### Step 1: Write the failing test for multi-device registration

Add to `cmd/syncvaultd/main_test.go`:

```go
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
	respA.Body.Close()
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("device A expected 200, got %d", respA.StatusCode)
	}

	reqB, _ := http.NewRequest("GET", ts.URL+"/v1/sync/pull?user_id="+userID+"&since=0", nil)
	reqB.Header.Set("Authorization", "Bearer "+tokenB)
	respB, err := client.Do(reqB)
	if err != nil {
		t.Fatalf("device B request: %v", err)
	}
	respB.Body.Close()
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
	sigB64 := base64.StdEncoding.EncodeString(ssh.Marshal(sig))
	token, err := authClient.Verify(ctx, userID, ch.ID, sigB64)
	if err != nil {
		t.Fatalf("verify %s: %v", deviceName, err)
	}
	return token.Token
}
```

### Step 2: Run test to verify it fails

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestMultipleDevicesCanAuthenticate`
Expected: FAIL (RegisterAuthorizedKeyWithDevice undefined, second device overwrites first)

### Step 3: Update schema migration

In `cmd/syncvaultd/main.go`, update `migrate()`:

```go
func (s *Server) migrate() error {
	_, err := s.db.Exec(`
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  ssh_pubkey TEXT NOT NULL,
  ssh_pubkey_fp TEXT NOT NULL,
  name TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  UNIQUE(ssh_pubkey_fp)
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_fp ON devices(ssh_pubkey_fp);

CREATE TABLE IF NOT EXISTS challenges (
  challenge_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  challenge BLOB NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS changes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  change_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  entity TEXT NOT NULL,
  ts INTEGER NOT NULL,
  nonce_b64 TEXT NOT NULL,
  ct_b64 TEXT NOT NULL,
  UNIQUE(user_id, change_id)
);

CREATE INDEX IF NOT EXISTS idx_changes_user_seq ON changes(user_id, seq);
CREATE INDEX IF NOT EXISTS idx_tokens_user_exp ON tokens(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_user_exp ON challenges(user_id, expires_at);
`)
	return err
}
```

### Step 4: Update register handler

Update `registerReq` and `handleRegister` in `cmd/syncvaultd/main.go`:

```go
type registerReq struct {
	UserID        string `json:"user_id"`
	SSHPubkeyOpen string `json:"ssh_pubkey_openssh"`
	DeviceID      string `json:"device_id,omitempty"`
	DeviceName    string `json:"device_name,omitempty"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.SSHPubkeyOpen = strings.TrimSpace(req.SSHPubkeyOpen)
	if req.UserID == "" || req.SSHPubkeyOpen == "" {
		fail(w, http.StatusBadRequest, "user_id and ssh_pubkey_openssh required")
		return
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHPubkeyOpen))
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid ssh public key")
		return
	}
	fp := ssh.FingerprintSHA256(pub)

	// Generate device_id if not provided
	deviceID := req.DeviceID
	if deviceID == "" {
		deviceID = randHex(16)
	}

	now := time.Now().Unix()

	// Ensure user exists
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO users(user_id, created_at) VALUES(?,?)`, req.UserID, now); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	// Insert or update device (by fingerprint to handle re-registration of same key)
	if _, err := s.db.Exec(`
INSERT INTO devices(device_id, user_id, ssh_pubkey, ssh_pubkey_fp, name, created_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(ssh_pubkey_fp) DO UPDATE SET
  name=COALESCE(excluded.name, devices.name),
  ssh_pubkey=excluded.ssh_pubkey
`, deviceID, req.UserID, req.SSHPubkeyOpen, fp, req.DeviceName, now); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, map[string]any{"ok": true, "ssh_fp": fp, "device_id": deviceID})
}
```

### Step 5: Update auth verification to use devices table

Update `fetchUserPublicKey` to look up by fingerprint in devices:

```go
func (s *Server) fetchDeviceByFingerprint(fp string) (deviceID string, userID string, pub ssh.PublicKey, err error) {
	var pubStr string
	err = s.db.QueryRow(`SELECT device_id, user_id, ssh_pubkey FROM devices WHERE ssh_pubkey_fp=?`, fp).Scan(&deviceID, &userID, &pubStr)
	if err != nil {
		return "", "", nil, err
	}
	pub, _, _, _, err = ssh.ParseAuthorizedKey([]byte(pubStr))
	return deviceID, userID, pub, err
}
```

Update challenge to work with fingerprint lookup. The flow changes:
1. Client provides `ssh_pubkey_fp` in challenge request (or we look up by user_id and return challenges for any device)
2. Verify looks up device by fingerprint from the signature

For simplicity, let's keep challenge by user_id but verify looks up the device:

Update `processVerify` in `cmd/syncvaultd/main.go`:

```go
func (s *Server) processVerify(ctx context.Context, req verifyReq) (verifyResp, int, error) {
	account, err := s.pbClient.GetAccountByUserID(ctx, req.UserID)
	if err != nil {
		return verifyResp{}, http.StatusUnauthorized, err
	}
	if !account.Active {
		return verifyResp{}, http.StatusForbidden, errors.New("account inactive")
	}

	// Load challenge
	challenge, expires, err := s.loadChallenge(req.UserID, req.ChallengeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return verifyResp{}, http.StatusNotFound, errors.New("unknown challenge")
		}
		return verifyResp{}, http.StatusInternalServerError, errors.New("db error")
	}
	if time.Now().Unix() > expires {
		return verifyResp{}, http.StatusUnauthorized, errors.New("challenge expired")
	}

	sig, err := parseSignature(req.SignatureB64)
	if err != nil {
		return verifyResp{}, http.StatusBadRequest, err
	}

	// Find device that can verify this signature
	deviceID, pub, err := s.findDeviceForSignature(req.UserID, challenge, sig)
	if err != nil {
		return verifyResp{}, http.StatusUnauthorized, errors.New("signature verification failed")
	}

	// Delete used challenge
	if _, err := s.db.Exec(`DELETE FROM challenges WHERE challenge_id=?`, req.ChallengeID); err != nil {
		return verifyResp{}, http.StatusInternalServerError, errors.New("db error")
	}

	// Update last_used_at
	s.db.Exec(`UPDATE devices SET last_used_at=? WHERE device_id=?`, time.Now().Unix(), deviceID)

	resp, err := s.issueTokenForDevice(req.UserID, deviceID)
	if err != nil {
		return verifyResp{}, http.StatusInternalServerError, errors.New("db error")
	}
	return resp, http.StatusOK, nil
}

func (s *Server) findDeviceForSignature(userID string, challenge []byte, sig *ssh.Signature) (string, ssh.PublicKey, error) {
	rows, err := s.db.Query(`SELECT device_id, ssh_pubkey FROM devices WHERE user_id=?`, userID)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var deviceID, pubStr string
		if err := rows.Scan(&deviceID, &pubStr); err != nil {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubStr))
		if err != nil {
			continue
		}
		if err := pub.Verify(challenge, sig); err == nil {
			return deviceID, pub, nil
		}
	}
	return "", nil, errors.New("no matching device")
}

func (s *Server) issueTokenForDevice(userID, deviceID string) (verifyResp, error) {
	token := "sv_" + randHex(32)
	tokenHash := hashToken(token)
	exp := time.Now().Add(12 * time.Hour).Unix()
	if _, err := s.db.Exec(`INSERT INTO tokens(token_hash, user_id, device_id, expires_at) VALUES(?,?,?,?)`, tokenHash, userID, deviceID, exp); err != nil {
		return verifyResp{}, err
	}
	return verifyResp{Token: token, ExpiresUnix: exp}, nil
}
```

### Step 6: Update vault auth client

Add to `vault/auth_ssh.go`:

```go
// RegisterAuthorizedKeyWithDevice registers a key with an optional device name.
func (c *AuthClient) RegisterAuthorizedKeyWithDevice(ctx context.Context, userID, authorizedKey, deviceName string) error {
	authorizedKey = strings.TrimSpace(authorizedKey)
	if authorizedKey == "" {
		return errors.New("authorized key required")
	}
	req := struct {
		UserID        string `json:"user_id"`
		SSHPubkeyOpen string `json:"ssh_pubkey_openssh"`
		DeviceName    string `json:"device_name,omitempty"`
	}{
		UserID:        userID,
		SSHPubkeyOpen: authorizedKey,
		DeviceName:    deviceName,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/v1/auth/register", req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register failed: %s", decodeError(resp))
	}
	return resp.Body.Close()
}
```

### Step 7: Run test to verify it passes

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestMultipleDevicesCanAuthenticate`
Expected: PASS

### Step 8: Write test for device listing

Add to `cmd/syncvaultd/main_test.go`:

```go
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
			Name     string `json:"name"`
		} `json:"devices"`
	}
	json.NewDecoder(resp.Body).Decode(&body)

	if len(body.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(body.Devices))
	}
}
```

### Step 9: Implement device list/revoke endpoints

Create `cmd/syncvaultd/devices.go`:

```go
// ABOUTME: Device management endpoints for listing and revoking devices.
// ABOUTME: Supports multi-device authentication model.

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type deviceInfo struct {
	DeviceID   string `json:"device_id"`
	Name       string `json:"name,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt *int64 `json:"last_used_at,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID := r.Context().Value(ctxUserIDKey{}).(string)

	rows, err := s.db.QueryContext(r.Context(), `
SELECT device_id, name, created_at, last_used_at, ssh_pubkey_fp
FROM devices WHERE user_id = ?
ORDER BY created_at DESC
`, userID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	devices := []deviceInfo{}
	for rows.Next() {
		var d deviceInfo
		var name *string
		var lastUsed *int64
		if err := rows.Scan(&d.DeviceID, &name, &d.CreatedAt, &lastUsed, &d.Fingerprint); err != nil {
			fail(w, http.StatusInternalServerError, "db error")
			return
		}
		if name != nil {
			d.Name = *name
		}
		d.LastUsedAt = lastUsed
		devices = append(devices, d)
	}

	ok(w, map[string]any{"devices": devices})
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID := r.Context().Value(ctxUserIDKey{}).(string)

	// Extract device_id from path: /v1/devices/{device_id}
	path := strings.TrimPrefix(r.URL.Path, "/v1/devices/")
	deviceID := strings.TrimSpace(path)
	if deviceID == "" {
		fail(w, http.StatusBadRequest, "device_id required")
		return
	}

	// Verify device belongs to user
	var owner string
	err := s.db.QueryRowContext(r.Context(), `SELECT user_id FROM devices WHERE device_id=?`, deviceID).Scan(&owner)
	if err != nil {
		fail(w, http.StatusNotFound, "device not found")
		return
	}
	if owner != userID {
		fail(w, http.StatusForbidden, "not your device")
		return
	}

	// Delete device and its tokens
	tx, _ := s.db.BeginTx(r.Context(), nil)
	defer tx.Rollback()

	tx.Exec(`DELETE FROM tokens WHERE device_id=?`, deviceID)
	tx.Exec(`DELETE FROM devices WHERE device_id=?`, deviceID)
	tx.Commit()

	ok(w, map[string]any{"ok": true, "revoked": deviceID})
}
```

### Step 10: Wire up device endpoints in handler

In `cmd/syncvaultd/main.go`, update `handler()`:

```go
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/auth/register", s.handleRegister)
	mux.HandleFunc("/v1/auth/challenge", s.handleChallenge)
	mux.HandleFunc("/v1/auth/verify", s.handleVerify)
	mux.HandleFunc("/v1/sync/push", s.withAuth(s.handlePush))
	mux.HandleFunc("/v1/sync/pull", s.withAuth(s.handlePull))
	mux.HandleFunc("/v1/devices", s.withAuth(s.handleListDevices))
	mux.HandleFunc("/v1/devices/", s.withAuth(s.handleRevokeDevice))
	return withJSON(withLogging(mux))
}
```

### Step 11: Run all tests

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/...`
Expected: All tests PASS

### Step 12: Commit

```bash
git add cmd/syncvaultd/main.go cmd/syncvaultd/devices.go cmd/syncvaultd/main_test.go vault/auth_ssh.go
git commit -m "feat(server): multi-device authentication support

- New devices table replacing single-key-per-user model
- Register endpoint creates device records
- Auth verifies signature against any user device
- List and revoke device endpoints
- Tokens track originating device"
```

---

## Task 4: Conflict Detection (Client-Side)

**Files:**
- Modify: `vault/change.go` (add BaseVersion)
- Modify: `cmd/internal/appcli/appcli.go` (version tracking)
- Create: `cmd/internal/appcli/conflict.go`
- Modify: `cmd/internal/appcli/appcli_test.go` (add tests)

### Step 1: Write the failing test

Create `cmd/internal/appcli/appcli_test.go`:

```go
// ABOUTME: Tests for appcli application layer.
// ABOUTME: Covers CRUD operations, sync, and conflict detection.

package appcli

import (
	"context"
	"testing"
)

func TestConflictDetection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	app, err := NewTestApp(dir)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	defer app.Close()

	// Create initial record (version 0)
	if err := app.Upsert(ctx, "todo", "item-1", map[string]any{"text": "original"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Simulate remote change with base_version=0 (no conflict)
	remoteChange := Change{
		Entity:      "todo",
		EntityID:    "item-1",
		BaseVersion: 0,
		Payload:     []byte(`{"text":"remote update"}`),
	}
	conflict, err := app.ApplyWithConflictCheck(ctx, remoteChange)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if conflict != nil {
		t.Fatalf("unexpected conflict on first remote change")
	}

	// Local record now at version 1
	// Simulate stale remote change with base_version=0 (conflict!)
	staleChange := Change{
		Entity:      "todo",
		EntityID:    "item-1",
		BaseVersion: 0, // Based on version 0, but local is now 1
		Payload:     []byte(`{"text":"stale update"}`),
	}
	conflict, err = app.ApplyWithConflictCheck(ctx, staleChange)
	if err != nil {
		t.Fatalf("apply stale: %v", err)
	}
	if conflict == nil {
		t.Fatalf("expected conflict for stale change")
	}
	if conflict.LocalVersion != 1 {
		t.Errorf("expected local version 1, got %d", conflict.LocalVersion)
	}
}
```

### Step 2: Run test to verify it fails

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/internal/appcli/... -run TestConflictDetection`
Expected: FAIL (NewTestApp undefined, ApplyWithConflictCheck undefined)

### Step 3: Add BaseVersion to Change

Modify `vault/change.go`:

```go
// Change is the plaintext logical event before encryption.
type Change struct {
	ChangeID    string          `json:"change_id"`
	Entity      string          `json:"entity"`
	EntityID    string          `json:"entity_id"`
	Op          Op              `json:"op"`
	TS          time.Time       `json:"ts"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	Deleted     bool            `json:"deleted,omitempty"`
	BaseVersion int64           `json:"base_version,omitempty"`
}

// NewChangeWithVersion builds a change that tracks the base version.
func NewChangeWithVersion(entity, entityID string, op Op, payload any, baseVersion int64) (Change, error) {
	c, err := NewChange(entity, entityID, op, payload)
	if err != nil {
		return Change{}, err
	}
	c.BaseVersion = baseVersion
	return c, nil
}
```

### Step 4: Update appcli schema to track version

Modify `cmd/internal/appcli/appcli.go` schema in `migrateAppDB`:

```go
func migrateAppDB(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS records (
  entity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  op TEXT NOT NULL,
  version INTEGER DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(entity, entity_id)
);
`)
	return err
}
```

### Step 5: Create conflict detection logic

Create `cmd/internal/appcli/conflict.go`:

```go
// ABOUTME: Conflict detection for multi-device sync scenarios.
// ABOUTME: Detects when remote changes are based on stale local versions.

package appcli

import (
	"context"
	"database/sql"
	"encoding/json"

	"suitesync/vault"
)

// Conflict represents a detected version conflict.
type Conflict struct {
	Entity       string
	EntityID     string
	LocalVersion int64
	LocalPayload json.RawMessage
	RemoteChange vault.Change
}

// ApplyWithConflictCheck applies a change, detecting version conflicts.
// Returns non-nil Conflict if the change's BaseVersion doesn't match local version.
func (a *App) ApplyWithConflictCheck(ctx context.Context, c vault.Change) (*Conflict, error) {
	// Get current local version
	var localVersion int64
	var localPayload string
	err := a.appDB.QueryRowContext(ctx, `
SELECT version, payload FROM records WHERE entity=? AND entity_id=?
`, c.Entity, c.EntityID).Scan(&localVersion, &localPayload)

	if err == sql.ErrNoRows {
		// New record, no conflict possible
		return nil, a.applyChange(ctx, c, 0)
	}
	if err != nil {
		return nil, err
	}

	// Check for conflict: remote change based on older version than local
	if c.BaseVersion < localVersion {
		return &Conflict{
			Entity:       c.Entity,
			EntityID:     c.EntityID,
			LocalVersion: localVersion,
			LocalPayload: json.RawMessage(localPayload),
			RemoteChange: c,
		}, nil
	}

	// No conflict, apply the change
	return nil, a.applyChange(ctx, c, localVersion)
}

func (a *App) applyChange(ctx context.Context, c vault.Change, currentVersion int64) error {
	newVersion := currentVersion + 1

	switch c.Op {
	case vault.OpDelete:
		_, err := a.appDB.ExecContext(ctx, `DELETE FROM records WHERE entity=? AND entity_id=?`, c.Entity, c.EntityID)
		return err
	case vault.OpUpsert, vault.OpAppend:
		_, err := a.appDB.ExecContext(ctx, `
INSERT INTO records(entity, entity_id, payload, op, version, updated_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(entity, entity_id) DO UPDATE SET
  payload=excluded.payload,
  op=excluded.op,
  version=excluded.version,
  updated_at=excluded.updated_at
`, c.Entity, c.EntityID, string(c.Payload), string(c.Op), newVersion, c.TS.Unix())
		return err
	}
	return nil
}

// GetVersion returns the current version of a record (0 if not exists).
func (a *App) GetVersion(ctx context.Context, entity, entityID string) (int64, error) {
	var version int64
	err := a.appDB.QueryRowContext(ctx, `
SELECT version FROM records WHERE entity=? AND entity_id=?
`, entity, entityID).Scan(&version)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return version, err
}
```

### Step 6: Add test helper

Add to `cmd/internal/appcli/appcli_test.go`:

```go
func NewTestApp(dir string) (*App, error) {
	// Minimal test app without sync capabilities
	appDBPath := filepath.Join(dir, "app.sqlite")
	appDB, err := sql.Open("sqlite", appDBPath)
	if err != nil {
		return nil, err
	}
	if err := migrateAppDB(appDB); err != nil {
		appDB.Close()
		return nil, err
	}
	return &App{appDB: appDB}, nil
}
```

Add necessary imports and expose appDB field or create accessor.

### Step 7: Run test to verify it passes

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/internal/appcli/... -run TestConflictDetection`
Expected: PASS

### Step 8: Update Upsert to track version in outgoing changes

Modify `Upsert` in `cmd/internal/appcli/appcli.go` to include base version:

```go
func (a *App) Upsert(ctx context.Context, entity, entityID string, payload any) error {
	// Get current version before update
	baseVersion, err := a.GetVersion(ctx, entity, entityID)
	if err != nil {
		return err
	}

	c, err := vault.NewChangeWithVersion(entity, entityID, vault.OpUpsert, payload, baseVersion)
	if err != nil {
		return err
	}
	// ... rest of encryption and enqueue logic
}
```

### Step 9: Run all appcli tests

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/internal/appcli/...`
Expected: All tests PASS

### Step 10: Commit

```bash
git add vault/change.go cmd/internal/appcli/appcli.go cmd/internal/appcli/conflict.go cmd/internal/appcli/appcli_test.go
git commit -m "feat(client): conflict detection with version tracking

- Add BaseVersion field to Change struct
- Track version in records table
- ApplyWithConflictCheck detects stale remote changes
- Upsert includes base_version in outgoing changes"
```

---

## Task 5: Snapshots & Compaction

**Files:**
- Modify: `cmd/syncvaultd/main.go` (schema, snapshot endpoint)
- Create: `cmd/syncvaultd/snapshot.go`
- Modify: `cmd/syncvaultd/main_test.go` (add tests)
- Modify: `vault/client_http.go` (add snapshot methods)

### Step 1: Write the failing test

Add to `cmd/syncvaultd/main_test.go`:

```go
func TestSnapshotAndPrune(t *testing.T) {
	env := newServerTestEnv(t)

	// Push 5 changes
	for i := 0; i < 5; i++ {
		change, _ := vault.NewChange("todo", fmt.Sprintf("item-%d", i), vault.OpUpsert, map[string]any{"n": i})
		changeBytes, _ := json.Marshal(change)
		envl, _ := vault.Encrypt(env.keys.EncKey, changeBytes, change.AAD(env.userID, "device-a"))

		client := vault.NewClient(vault.SyncConfig{BaseURL: env.server.URL, DeviceID: "device-a", AuthToken: env.token})
		client.Push(env.ctx, env.userID, []vault.PushItem{{
			ChangeID: change.ChangeID,
			Entity:   change.Entity,
			TS:       change.TS.Unix(),
			Env:      envl,
		}})
	}

	// Create snapshot at current seq
	snapshotPayload := []byte(`[{"entity_id":"item-0"},{"entity_id":"item-1"}]`)
	snapshotEnv, _ := vault.Encrypt(env.keys.EncKey, snapshotPayload, []byte("snapshot:"+env.userID+":todo"))

	req := snapshotReq{
		UserID: env.userID,
		Entity: "todo",
		Env:    envelope{NonceB64: snapshotEnv.NonceB64, CTB64: snapshotEnv.CTB64},
	}
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", env.server.URL+"/v1/sync/snapshot", bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+env.token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("snapshot request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Pull from seq=0 should return snapshot
	pullResp, err := vault.NewClient(vault.SyncConfig{BaseURL: env.server.URL, DeviceID: "device-b", AuthToken: env.token}).
		PullWithSnapshot(env.ctx, env.userID, 0, "todo")
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if pullResp.Snapshot == nil {
		t.Fatalf("expected snapshot in response")
	}
}
```

### Step 2: Run test to verify it fails

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestSnapshotAndPrune`
Expected: FAIL (snapshotReq undefined, PullWithSnapshot undefined)

### Step 3: Add snapshot table to schema

In `cmd/syncvaultd/main.go` `migrate()`, add:

```sql
CREATE TABLE IF NOT EXISTS snapshots (
  snapshot_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  entity TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  min_seq INTEGER NOT NULL,
  nonce_b64 TEXT NOT NULL,
  ct_b64 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_user_entity ON snapshots(user_id, entity, created_at DESC);
```

### Step 4: Create snapshot handler

Create `cmd/syncvaultd/snapshot.go`:

```go
// ABOUTME: Snapshot creation and retrieval for efficient sync bootstrap.
// ABOUTME: Enables compaction of old changes and fast new-device onboarding.

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type snapshotReq struct {
	UserID string   `json:"user_id"`
	Entity string   `json:"entity"`
	Env    envelope `json:"env"`
}

type snapshotResp struct {
	SnapshotID string `json:"snapshot_id"`
	MinSeq     int64  `json:"min_seq"`
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	var req snapshotReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.Entity = strings.TrimSpace(req.Entity)

	if req.UserID != authUser {
		fail(w, http.StatusForbidden, "token user mismatch")
		return
	}
	if req.Entity == "" || req.Env.NonceB64 == "" || req.Env.CTB64 == "" {
		fail(w, http.StatusBadRequest, "entity and env required")
		return
	}

	// Get current max seq for this user/entity
	var maxSeq int64
	s.db.QueryRowContext(r.Context(), `
SELECT COALESCE(MAX(seq), 0) FROM changes WHERE user_id=? AND entity=?
`, req.UserID, req.Entity).Scan(&maxSeq)

	snapshotID := randHex(16)
	now := time.Now().Unix()

	if _, err := s.db.ExecContext(r.Context(), `
INSERT INTO snapshots(snapshot_id, user_id, entity, created_at, min_seq, nonce_b64, ct_b64)
VALUES(?,?,?,?,?,?,?)
`, snapshotID, req.UserID, req.Entity, now, maxSeq, req.Env.NonceB64, req.Env.CTB64); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, snapshotResp{SnapshotID: snapshotID, MinSeq: maxSeq})
}

type snapshotInfo struct {
	SnapshotID string   `json:"snapshot_id"`
	MinSeq     int64    `json:"min_seq"`
	CreatedAt  int64    `json:"created_at"`
	Env        envelope `json:"env"`
}

func (s *Server) getLatestSnapshot(ctx context.Context, userID, entity string) (*snapshotInfo, error) {
	var info snapshotInfo
	err := s.db.QueryRowContext(ctx, `
SELECT snapshot_id, min_seq, created_at, nonce_b64, ct_b64
FROM snapshots
WHERE user_id=? AND entity=?
ORDER BY created_at DESC
LIMIT 1
`, userID, entity).Scan(&info.SnapshotID, &info.MinSeq, &info.CreatedAt, &info.Env.NonceB64, &info.Env.CTB64)
	if err != nil {
		return nil, err
	}
	return &info, nil
}
```

### Step 5: Update pull to support snapshots

Modify `handlePull` in `cmd/syncvaultd/main.go` to optionally include snapshot:

```go
type pullResp struct {
	Items    []pullItem    `json:"items"`
	Snapshot *snapshotInfo `json:"snapshot,omitempty"`
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	// ... existing validation ...

	entity := strings.TrimSpace(r.URL.Query().Get("entity"))
	includeSnapshot := since == 0 && entity != ""

	resp := pullResp{}

	// If pulling from 0 and entity specified, include snapshot
	if includeSnapshot {
		snapshot, err := s.getLatestSnapshot(r.Context(), userID, entity)
		if err == nil && snapshot != nil {
			resp.Snapshot = snapshot
			since = snapshot.MinSeq // Only get changes after snapshot
		}
	}

	// ... existing query logic, using updated since ...
}
```

### Step 6: Add client method for snapshot pull

Add to `vault/client_http.go`:

```go
// PullRespWithSnapshot extends PullResp with optional snapshot.
type PullRespWithSnapshot struct {
	Items    []PullItem
	Snapshot *SnapshotInfo
}

type SnapshotInfo struct {
	SnapshotID string
	MinSeq     int64
	CreatedAt  int64
	Env        Envelope
}

// PullWithSnapshot fetches changes with optional snapshot for bootstrap.
func (c *Client) PullWithSnapshot(ctx context.Context, userID string, since int64, entity string) (PullRespWithSnapshot, error) {
	url := fmt.Sprintf("%s/v1/sync/pull?user_id=%s&since=%d", c.baseURL, userID, since)
	if entity != "" {
		url += "&entity=" + entity
	}
	// ... rest of HTTP logic, parse snapshot from response ...
}
```

### Step 7: Run test to verify it passes

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestSnapshotAndPrune`
Expected: PASS

### Step 8: Add compaction endpoint

Add to `cmd/syncvaultd/snapshot.go`:

```go
func (s *Server) handleCompact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	entity := strings.TrimSpace(r.URL.Query().Get("entity"))
	if entity == "" {
		fail(w, http.StatusBadRequest, "entity required")
		return
	}

	// Get oldest snapshot's min_seq
	var minSeq int64
	err := s.db.QueryRowContext(r.Context(), `
SELECT MIN(min_seq) FROM snapshots WHERE user_id=? AND entity=?
`, authUser, entity).Scan(&minSeq)
	if err != nil {
		fail(w, http.StatusInternalServerError, "no snapshot found")
		return
	}

	// Delete changes older than snapshot
	res, err := s.db.ExecContext(r.Context(), `
DELETE FROM changes WHERE user_id=? AND entity=? AND seq <= ?
`, authUser, entity, minSeq)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	deleted, _ := res.RowsAffected()
	ok(w, map[string]any{"ok": true, "deleted_changes": deleted})
}
```

### Step 9: Wire up endpoints

In `handler()`:

```go
mux.HandleFunc("/v1/sync/snapshot", s.withAuth(s.handleSnapshot))
mux.HandleFunc("/v1/sync/compact", s.withAuth(s.handleCompact))
```

### Step 10: Run all tests

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/...`
Expected: All tests PASS

### Step 11: Commit

```bash
git add cmd/syncvaultd/main.go cmd/syncvaultd/snapshot.go cmd/syncvaultd/main_test.go vault/client_http.go
git commit -m "feat(server): snapshot creation and compaction

- Snapshots table stores encrypted full-state per entity
- Pull from seq=0 returns latest snapshot + delta changes
- Compact endpoint prunes changes older than snapshot
- Enables bounded storage growth and fast bootstrap"
```

---

## Task 6: Seed Rotation

**Files:**
- Create: `cmd/sweet/rotate.go`
- Modify: `cmd/syncvaultd/main.go` (migrate endpoint)
- Create: `cmd/syncvaultd/migrate.go`
- Add tests

### Step 1: Write the failing test

Add to `cmd/syncvaultd/main_test.go`:

```go
func TestAccountMigration(t *testing.T) {
	env := newServerTestEnv(t)

	// Push some data under old user
	env.pushChange(t, "device-a")

	// Generate new keys (simulating seed rotation)
	newSeed, _, _ := vault.NewSeedPhrase()
	newSeedParsed, _ := vault.ParseSeedPhrase(newSeed)
	newKeys, _ := vault.DeriveKeys(newSeedParsed, "", vault.DefaultKDFParams())
	newUserID := newKeys.UserID()

	// Call migrate endpoint
	migrateReq := map[string]any{
		"old_user_id": env.userID,
		"new_user_id": newUserID,
		"confirm":     true,
	}
	body, _ := json.Marshal(migrateReq)
	req, _ := http.NewRequest("POST", env.server.URL+"/v1/account/migrate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+env.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("migrate request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, errResp)
	}

	// Verify devices moved to new user
	var count int
	env.srv.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=?`, newUserID).Scan(&count)
	if count == 0 {
		t.Fatalf("expected devices under new user_id")
	}

	// Verify old tokens invalidated
	client := &http.Client{}
	checkReq, _ := http.NewRequest("GET", env.server.URL+"/v1/sync/pull?user_id="+env.userID+"&since=0", nil)
	checkReq.Header.Set("Authorization", "Bearer "+env.token)
	checkResp, _ := client.Do(checkReq)
	checkResp.Body.Close()
	if checkResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token should be invalidated, got %d", checkResp.StatusCode)
	}
}
```

### Step 2: Run test to verify it fails

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestAccountMigration`
Expected: FAIL (404 or endpoint not found)

### Step 3: Create migrate endpoint

Create `cmd/syncvaultd/migrate.go`:

```go
// ABOUTME: Account migration endpoint for seed rotation.
// ABOUTME: Transfers devices and invalidates old tokens when user rotates their seed.

package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

type migrateReq struct {
	OldUserID string `json:"old_user_id"`
	NewUserID string `json:"new_user_id"`
	Confirm   bool   `json:"confirm"`
}

type migrateResp struct {
	OK              bool  `json:"ok"`
	MigratedDevices int64 `json:"migrated_devices"`
}

func (s *Server) handleMigrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	var req migrateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.OldUserID = strings.TrimSpace(req.OldUserID)
	req.NewUserID = strings.TrimSpace(req.NewUserID)

	// Verify caller owns the old account
	if req.OldUserID != authUser {
		fail(w, http.StatusForbidden, "token user mismatch")
		return
	}
	if req.NewUserID == "" {
		fail(w, http.StatusBadRequest, "new_user_id required")
		return
	}
	if !req.Confirm {
		fail(w, http.StatusBadRequest, "confirm required")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback()

	// Create new user record
	tx.Exec(`INSERT OR IGNORE INTO users(user_id, created_at) VALUES(?, ?)`, req.NewUserID, now())

	// Move devices to new user
	res, err := tx.Exec(`UPDATE devices SET user_id=? WHERE user_id=?`, req.NewUserID, req.OldUserID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}
	migratedDevices, _ := res.RowsAffected()

	// Invalidate all old tokens
	tx.Exec(`DELETE FROM tokens WHERE user_id=?`, req.OldUserID)

	// Update PocketBase (if configured)
	if err := s.pbClient.MigrateUserID(r.Context(), req.OldUserID, req.NewUserID); err != nil {
		// Log but don't fail - PocketBase update can be retried
		log.Printf("pocketbase migration warning: %v", err)
	}

	if err := tx.Commit(); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, migrateResp{OK: true, MigratedDevices: migratedDevices})
}

func now() int64 {
	return time.Now().Unix()
}
```

### Step 4: Add MigrateUserID to pocketbase client interface

In `internal/pocketbase/client.go`, add to interface:

```go
type Client interface {
	GetAccountByUserID(ctx context.Context, userID string) (AccountInfo, error)
	IncrementUsage(ctx context.Context, userID string, changes int) error
	MigrateUserID(ctx context.Context, oldUserID, newUserID string) error
}
```

Add noop implementation:

```go
func (NoopClient) MigrateUserID(ctx context.Context, oldUserID, newUserID string) error {
	return nil
}
```

### Step 5: Wire up migrate endpoint

In `handler()`:

```go
mux.HandleFunc("/v1/account/migrate", s.withAuth(s.handleMigrate))
```

### Step 6: Run test to verify it passes

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./cmd/syncvaultd/... -run TestAccountMigration`
Expected: PASS

### Step 7: Create sweet rotate-seed command

Create `cmd/sweet/rotate.go`:

```go
// ABOUTME: Seed rotation command for recovering from compromised seeds.
// ABOUTME: Re-encrypts all data with new keys and migrates account.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"suitesync/vault"
)

func cmdRotateSeed(args []string) error {
	fs := flag.NewFlagSet("rotate-seed", flag.ExitOnError)
	oldSeed := fs.String("old-seed", "", "current seed phrase")
	newSeed := fs.String("new-seed", "", "new seed phrase (generated if empty)")
	passphrase := fs.String("passphrase", "", "passphrase for key derivation")
	serverURL := fs.String("server", "http://localhost:8080", "sync server URL")
	appDB := fs.String("app-db", "", "path to app database")
	fs.Parse(args)

	if *oldSeed == "" || *appDB == "" {
		return fmt.Errorf("old-seed and app-db required")
	}

	ctx := context.Background()

	// Derive old keys
	oldSeedParsed, err := vault.ParseSeedPhrase(*oldSeed)
	if err != nil {
		return fmt.Errorf("parse old seed: %w", err)
	}
	oldKeys, err := vault.DeriveKeys(oldSeedParsed, *passphrase, vault.DefaultKDFParams())
	if err != nil {
		return fmt.Errorf("derive old keys: %w", err)
	}

	// Generate or parse new seed
	var newSeedParsed vault.SeedPhrase
	var newSeedPhrase string
	if *newSeed == "" {
		newSeedPhrase, newSeedParsed, err = vault.NewSeedPhrase()
		if err != nil {
			return fmt.Errorf("generate new seed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Generated new seed phrase:\n%s\n\nSAVE THIS SECURELY!\n\n", newSeedPhrase)
	} else {
		newSeedParsed, err = vault.ParseSeedPhrase(*newSeed)
		if err != nil {
			return fmt.Errorf("parse new seed: %w", err)
		}
		newSeedPhrase = *newSeed
	}

	newKeys, err := vault.DeriveKeys(newSeedParsed, *passphrase, vault.DefaultKDFParams())
	if err != nil {
		return fmt.Errorf("derive new keys: %w", err)
	}

	fmt.Printf("Old user_id: %s\n", oldKeys.UserID())
	fmt.Printf("New user_id: %s\n", newKeys.UserID())

	// TODO: Full implementation:
	// 1. Pull all data with old keys
	// 2. Re-encrypt with new keys
	// 3. Push under new user_id
	// 4. Call /v1/account/migrate
	// 5. Verify and cleanup

	fmt.Println("\nSeed rotation prepared. Implementation continues in next phase.")
	return nil
}
```

### Step 8: Run all tests

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test -v ./...`
Expected: All tests PASS

### Step 9: Commit

```bash
git add cmd/syncvaultd/migrate.go cmd/syncvaultd/main.go cmd/syncvaultd/main_test.go cmd/sweet/rotate.go internal/pocketbase/client.go
git commit -m "feat: seed rotation with account migration

- Server endpoint POST /v1/account/migrate
- Transfers devices to new user_id
- Invalidates old tokens
- sweet rotate-seed command scaffolding
- PocketBase client migration method"
```

---

## Summary

| Task | Files | Estimated Complexity |
|------|-------|---------------------|
| 1. Background Cleanup | 2 new, 1 modified | Low |
| 2. Rate Limiting | 1 new, 2 modified | Low |
| 3. Multi-Device Auth | 1 new, 3 modified | Medium |
| 4. Conflict Detection | 1 new, 2 modified | Medium |
| 5. Snapshots | 1 new, 2 modified | High |
| 6. Seed Rotation | 2 new, 3 modified | High |

Each task is independently testable and can be deployed incrementally.
