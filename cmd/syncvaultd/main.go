package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/ssh"

	"suitesync/internal/pocketbase"
)

// Server bundles state for syncvaultd handlers.
type Server struct {
	db       *sql.DB
	pbClient pocketbase.Client
	limiters *rateLimiterStore
}

func main() {
	addr := env("ADDR", ":8080")
	dbPath := env("DB_PATH", "./syncvault.sqlite")
	flag.StringVar(&addr, "addr", addr, "listen address")
	flag.StringVar(&dbPath, "db", dbPath, "sqlite db path")
	flag.Parse()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1)

	pbClient := initPocketBaseClient()

	srv := &Server{
		db:       db,
		pbClient: pbClient,
		limiters: newRateLimiterStore(DefaultRateLimitConfig()),
	}
	if err := srv.migrate(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv.startCleanupRoutine(ctx)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("syncvaultd listening on %s (db=%s)", addr, dbPath)
	if err := httpSrv.ListenAndServe(); err != nil {
		cancel()
		log.Fatal(err)
	}
}

func (s *Server) migrate() error {
	schema := buildSchema()
	_, err := s.db.Exec(schema)
	return err
}

func buildSchema() string {
	return `
PRAGMA journal_mode=WAL;
` + schemaUsers() + schemaDevices() + schemaAuth() + schemaChanges() + schemaSnapshots()
}

func schemaUsers() string {
	return `
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);
`
}

func schemaDevices() string {
	return `
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
`
}

func schemaAuth() string {
	return `
CREATE TABLE IF NOT EXISTS challenges (
  challenge_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  challenge BLOB NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL DEFAULT '',
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_device ON tokens(device_id);
CREATE INDEX IF NOT EXISTS idx_tokens_user_exp ON tokens(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_user_exp ON challenges(user_id, expires_at);
`
}

func schemaChanges() string {
	return `
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
`
}

func schemaSnapshots() string {
	return `
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
`
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/auth/register", s.handleRegister)
	mux.HandleFunc("/v1/auth/challenge", s.handleChallenge)
	mux.HandleFunc("/v1/auth/verify", s.handleVerify)
	mux.HandleFunc("/v1/sync/push", s.withAuth(s.handlePush))
	mux.HandleFunc("/v1/sync/pull", s.withAuth(s.handlePull))
	mux.HandleFunc("/v1/sync/snapshot", s.withAuth(s.handleSnapshot))
	mux.HandleFunc("/v1/sync/compact", s.withAuth(s.handleCompact))
	mux.HandleFunc("/v1/devices", s.withAuth(s.handleListDevices))
	mux.HandleFunc("/v1/devices/", s.withAuth(s.handleRevokeDevice))
	mux.HandleFunc("/v1/account/migrate", s.withAuth(s.handleMigrate))
	return withJSON(withLogging(mux))
}

// register

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

// challenge

type challengeReq struct {
	UserID string `json:"user_id"`
}

type challengeResp struct {
	ChallengeID   string `json:"challenge_id"`
	ChallengeB64  string `json:"challenge_b64"`
	ExpiresUnix   int64  `json:"expires_unix"`
	SigningString string `json:"signing_hint,omitempty"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req challengeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}
	userID := strings.TrimSpace(req.UserID)
	if userID == "" {
		fail(w, http.StatusBadRequest, "user_id required")
		return
	}

	var existing string
	if err := s.db.QueryRow(`SELECT user_id FROM users WHERE user_id=?`, userID).Scan(&existing); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, http.StatusNotFound, "unknown user_id")
			return
		}
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	chID := randHex(16)
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		fail(w, http.StatusInternalServerError, "rng error")
		return
	}
	expires := time.Now().Add(2 * time.Minute).Unix()

	if _, err := s.db.Exec(`
INSERT INTO challenges(challenge_id, user_id, challenge, expires_at)
VALUES(?,?,?,?)
`, chID, userID, challenge, expires); err != nil {
		fail(w, http.StatusInternalServerError, "db error")
		return
	}

	ok(w, challengeResp{
		ChallengeID:   chID,
		ChallengeB64:  base64.StdEncoding.EncodeToString(challenge),
		ExpiresUnix:   expires,
		SigningString: "Sign the base64-decoded challenge bytes with your SSH private key.",
	})
}

// verify -> token

type verifyReq struct {
	UserID       string `json:"user_id"`
	ChallengeID  string `json:"challenge_id"`
	SignatureB64 string `json:"signature_b64"`
}

type verifyResp struct {
	Token       string `json:"token"`
	ExpiresUnix int64  `json:"expires_unix"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	req, err := decodeVerifyRequest(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, status, err := s.processVerify(r.Context(), req)
	if err != nil {
		fail(w, status, err.Error())
		return
	}
	ok(w, resp)
}

func decodeVerifyRequest(r *http.Request) (verifyReq, error) {
	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return verifyReq{}, errors.New("invalid json")
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.ChallengeID = strings.TrimSpace(req.ChallengeID)
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	if req.UserID == "" || req.ChallengeID == "" || req.SignatureB64 == "" {
		return verifyReq{}, errors.New("user_id, challenge_id, signature_b64 required")
	}
	return req, nil
}

func (s *Server) processVerify(ctx context.Context, req verifyReq) (verifyResp, int, error) {
	account, err := s.pbClient.GetAccountByUserID(ctx, req.UserID)
	if err != nil {
		return verifyResp{}, http.StatusUnauthorized, err
	}
	if !account.Active {
		return verifyResp{}, http.StatusForbidden, errors.New("account inactive")
	}

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
	deviceID, _, err := s.findDeviceForSignature(req.UserID, challenge, sig)
	if err != nil {
		return verifyResp{}, http.StatusUnauthorized, errors.New("signature verification failed")
	}

	// Delete used challenge
	if _, err := s.db.Exec(`DELETE FROM challenges WHERE challenge_id=?`, req.ChallengeID); err != nil {
		return verifyResp{}, http.StatusInternalServerError, errors.New("db error")
	}

	// Update last_used_at
	_, _ = s.db.Exec(`UPDATE devices SET last_used_at=? WHERE device_id=?`, time.Now().Unix(), deviceID)

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
	defer func() {
		_ = rows.Close()
	}()

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

// auth middleware

type ctxUserIDKey struct{}
type ctxDeviceIDKey struct{}

type authInfo struct {
	userID   string
	deviceID string
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := s.authUser(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, err.Error())
			return
		}

		// Rate limit check
		if s.limiters != nil {
			limiter := s.limiters.get(info.userID)
			if !limiter.Allow() {
				fail(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}

		ctx := context.WithValue(r.Context(), ctxUserIDKey{}, info.userID)
		ctx = context.WithValue(ctx, ctxDeviceIDKey{}, info.deviceID)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) authUser(r *http.Request) (authInfo, error) {
	h := r.Header.Get("Authorization")
	if h == "" || !strings.HasPrefix(h, "Bearer ") {
		return authInfo{}, errors.New("missing bearer token")
	}
	raw := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if raw == "" {
		return authInfo{}, errors.New("missing bearer token")
	}
	th := hashToken(raw)

	var userID string
	var deviceID string
	var exp int64
	if err := s.db.QueryRow(`SELECT user_id, device_id, expires_at FROM tokens WHERE token_hash=?`, th).Scan(&userID, &deviceID, &exp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authInfo{}, errors.New("invalid token")
		}
		return authInfo{}, errors.New("db error")
	}
	if time.Now().Unix() > exp {
		return authInfo{}, errors.New("token expired")
	}
	return authInfo{userID: userID, deviceID: deviceID}, nil
}

// push/pull

type pushReq struct {
	UserID   string     `json:"user_id"`
	DeviceID string     `json:"device_id"`
	Changes  []pushItem `json:"changes"`
}

type pushItem struct {
	ChangeID string   `json:"change_id"`
	Entity   string   `json:"entity"`
	TS       int64    `json:"ts"`
	Env      envelope `json:"env"`
	DeviceID string   `json:"device_id,omitempty"` // Optional per-item device_id (overrides request-level)
}

type envelope struct {
	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`
}

type pushResp struct {
	AckChangeIDs []string `json:"ack_change_ids"`
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	req, err := decodePushRequest(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.UserID != authUser {
		fail(w, http.StatusForbidden, "token user mismatch")
		return
	}

	ack, err := s.insertChanges(r.Context(), req)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}

	ok(w, pushResp{AckChangeIDs: ack})
}

func decodePushRequest(r *http.Request) (pushReq, error) {
	var req pushReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return pushReq{}, errors.New("invalid json")
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	if req.UserID == "" || req.DeviceID == "" {
		return pushReq{}, errors.New("user_id and device_id required")
	}
	return req, nil
}

func (s *Server) insertChanges(ctx context.Context, req pushReq) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.New("db error")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	stmt, err := tx.PrepareContext(ctx, `
INSERT OR IGNORE INTO changes(user_id, change_id, device_id, entity, ts, nonce_b64, ct_b64)
VALUES(?,?,?,?,?,?,?)
`)
	if err != nil {
		return nil, errors.New("db error")
	}
	defer func() {
		_ = stmt.Close()
	}()

	ack := make([]string, 0, len(req.Changes))
	for _, it := range req.Changes {
		if it.ChangeID == "" || it.Entity == "" || it.Env.NonceB64 == "" || it.Env.CTB64 == "" {
			continue
		}
		ts := it.TS
		if ts == 0 {
			ts = time.Now().Unix()
		}
		// Use per-item device_id if provided, otherwise fall back to request-level device_id
		deviceID := it.DeviceID
		if deviceID == "" {
			deviceID = req.DeviceID
		}
		if _, err := stmt.ExecContext(ctx, req.UserID, it.ChangeID, deviceID, it.Entity, ts, it.Env.NonceB64, it.Env.CTB64); err != nil {
			return nil, errors.New("db error")
		}
		ack = append(ack, it.ChangeID)
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.New("db error")
	}
	if len(ack) > 0 {
		if err := s.pbClient.IncrementUsage(ctx, req.UserID, len(ack)); err != nil {
			log.Printf("pocketbase usage update failed: %v", err)
		}
	}
	return ack, nil
}

type pullResp struct {
	Items    []pullItem    `json:"items"`
	Snapshot *snapshotInfo `json:"snapshot,omitempty"`
}

type pullItem struct {
	Seq      int64    `json:"seq"`
	ChangeID string   `json:"change_id"`
	DeviceID string   `json:"device_id"`
	Entity   string   `json:"entity"`
	Env      envelope `json:"env"`
	TS       int64    `json:"ts"`
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authUser := r.Context().Value(ctxUserIDKey{}).(string)

	userID, since, entity, err := parsePullParams(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if userID != authUser {
		fail(w, http.StatusForbidden, "token user mismatch")
		return
	}

	resp, err := s.buildPullResponse(r.Context(), userID, since, entity)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, resp)
}

func parsePullParams(r *http.Request) (userID string, since int64, entity string, err error) {
	userID = strings.TrimSpace(r.URL.Query().Get("user_id"))
	sinceStr := strings.TrimSpace(r.URL.Query().Get("since"))
	if userID == "" || sinceStr == "" {
		return "", 0, "", errors.New("user_id and since required")
	}
	since, err = strconv.ParseInt(sinceStr, 10, 64)
	if err != nil || since < 0 {
		return "", 0, "", errors.New("invalid since")
	}
	entity = strings.TrimSpace(r.URL.Query().Get("entity"))
	return userID, since, entity, nil
}

func (s *Server) buildPullResponse(ctx context.Context, userID string, since int64, entity string) (pullResp, error) {
	resp := pullResp{}

	// Include snapshot if pulling from 0 with entity specified
	if since == 0 && entity != "" {
		snapshot, err := s.getLatestSnapshot(ctx, userID, entity)
		if err == nil && snapshot != nil {
			resp.Snapshot = snapshot
			since = snapshot.MinSeq
		}
	}

	items, err := s.queryChanges(ctx, userID, since)
	if err != nil {
		return pullResp{}, err
	}
	resp.Items = items
	return resp, nil
}

func (s *Server) queryChanges(ctx context.Context, userID string, since int64) ([]pullItem, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT seq, change_id, device_id, entity, ts, nonce_b64, ct_b64
FROM changes
WHERE user_id = ? AND seq > ?
ORDER BY seq ASC
LIMIT 500
`, userID, since)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var items []pullItem
	for rows.Next() {
		var it pullItem
		if err := rows.Scan(&it.Seq, &it.ChangeID, &it.DeviceID, &it.Entity, &it.TS, &it.Env.NonceB64, &it.Env.CTB64); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// helpers

func ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]any{"error": msg}); err != nil {
		log.Printf("write error response: %v", err)
	}
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func withJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func env(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func initPocketBaseClient() pocketbase.Client {
	base := strings.TrimSpace(os.Getenv("POCKETBASE_URL"))
	token := strings.TrimSpace(os.Getenv("POCKETBASE_ADMIN_TOKEN"))
	if base == "" || token == "" {
		return pocketbase.NoopClient{}
	}
	return &pocketbase.HTTPClient{
		BaseURL: base,
		Token:   token,
	}
}

func (s *Server) loadChallenge(userID, challengeID string) ([]byte, int64, error) {
	var ch []byte
	var expires int64
	err := s.db.QueryRow(`SELECT challenge, expires_at FROM challenges WHERE challenge_id=? AND user_id=?`, challengeID, userID).Scan(&ch, &expires)
	return ch, expires, err
}

func parseSignature(sigB64 string) (*ssh.Signature, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("invalid signature_b64")
	}
	sig := &ssh.Signature{}
	if err := ssh.Unmarshal(sigBytes, sig); err != nil {
		return nil, errors.New("invalid signature encoding")
	}
	return sig, nil
}
