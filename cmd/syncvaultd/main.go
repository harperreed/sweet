// ABOUTME: SyncVaultd is the server backend for SyncVault, providing encrypted data sync.
// ABOUTME: Handles SSH-based auth, multi-device sync, and PocketBase integration for accounts.

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"golang.org/x/crypto/ssh"

	pbclient "suitesync/internal/pocketbase"

	_ "suitesync/cmd/syncvaultd/migrations" // Import migrations
)

// Server bundles state for syncvaultd handlers.
type Server struct {
	app          core.App
	pbClient     pbclient.Client
	limiters     *rateLimiterStore // Per-user rate limiting for authenticated endpoints
	authLimiters *rateLimiterStore // Per-IP rate limiting for auth endpoints
}

func main() {
	app := pocketbase.New()

	// Initialize PocketBase client for external PB instance (if configured)
	pbClient := initPocketBaseClient()

	// Create single server instance for routes and cleanup
	srv := &Server{
		app:          app,
		pbClient:     pbClient,
		limiters:     newRateLimiterStore(DefaultRateLimitConfig()),
		authLimiters: newRateLimiterStore(AuthRateLimitConfig()),
	}

	// Register custom routes
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		srv.registerRoutes(se.Router)
		return se.Next()
	})

	// Start cleanup routine when app starts
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		ctx := context.Background()
		srv.startCleanupRoutine(ctx)
		return se.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

func (s *Server) registerRoutes(r *router.Router[*core.RequestEvent]) {
	r.GET("/healthz", func(e *core.RequestEvent) error {
		return e.NoContent(http.StatusOK)
	})

	// Auth endpoints (with IP-based rate limiting)
	// SSH auth (legacy - to be removed)
	r.POST("/v1/auth/register", s.wrapHandler(s.withIPRateLimit(s.handleRegister)))
	r.POST("/v1/auth/challenge", s.wrapHandler(s.withIPRateLimit(s.handleChallenge)))
	r.POST("/v1/auth/verify", s.wrapHandler(s.withIPRateLimit(s.handleVerify)))

	// PocketBase email/password auth (new)
	r.POST("/v1/auth/pb/register", s.wrapHandler(s.withIPRateLimit(s.handlePBRegister)))
	r.POST("/v1/auth/pb/login", s.wrapHandler(s.withIPRateLimit(s.handlePBLogin)))
	r.POST("/v1/auth/pb/refresh", s.wrapHandler(s.withIPRateLimit(s.handlePBRefresh)))

	// Sync endpoints (protected)
	r.POST("/v1/sync/push", s.wrapHandler(s.withAuth(s.handlePush)))
	r.GET("/v1/sync/pull", s.wrapHandler(s.withAuth(s.handlePull)))
	r.POST("/v1/sync/snapshot", s.wrapHandler(s.withAuth(s.handleSnapshot)))
	r.POST("/v1/sync/compact", s.wrapHandler(s.withAuth(s.handleCompact)))

	// Device management (protected)
	r.GET("/v1/devices", s.wrapHandler(s.withAuth(s.handleListDevices)))
	r.DELETE("/v1/devices/:deviceId", s.wrapHandler(s.withAuth(s.handleRevokeDevice)))

	// Account management (protected)
	r.POST("/v1/account/migrate", s.wrapHandler(s.withAuth(s.handleMigrate)))
}

// wrapHandler converts http.HandlerFunc to PocketBase RequestHandler.
func (s *Server) wrapHandler(h http.HandlerFunc) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		h(e.Response, e.Request)
		return nil
	}
}

// withIPRateLimit applies per-IP rate limiting for auth endpoints.
// This protects against brute-force attacks on unauthenticated endpoints.
func (s *Server) withIPRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authLimiters != nil {
			clientIP := getClientIP(r)
			limiter := s.authLimiters.get(clientIP)
			if !limiter.Allow() {
				fail(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		next(w, r)
	}
}

// register

type registerReq struct {
	UserID        string `json:"user_id"`
	SSHPubkeyOpen string `json:"ssh_pubkey_openssh"`
	DeviceID      string `json:"device_id,omitempty"`
	DeviceName    string `json:"device_name,omitempty"`
	Force         bool   `json:"force,omitempty"` // Allow re-registering key to different user
}

//nolint:funlen,nestif // SSH auth registration requires multiple steps with nested ownership checks.
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

	// Ensure user exists
	usersCol, err := s.app.FindCollectionByNameOrId("sync_users")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	_, err = s.app.FindFirstRecordByFilter(usersCol, "user_id = {:user_id}", map[string]any{"user_id": req.UserID})
	if err != nil {
		// User doesn't exist, create it
		userRecord := core.NewRecord(usersCol)
		userRecord.Set("user_id", req.UserID)
		if err := s.app.Save(userRecord); err != nil {
			log.Printf("register user insert error: %v", err)
			fail(w, http.StatusInternalServerError, "db error")
			return
		}
	}

	// Check if device with this fingerprint exists
	devicesCol, err := s.app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	existingDevice, err := s.app.FindFirstRecordByFilter(devicesCol, "ssh_pubkey_fp = {:fp}", map[string]any{"fp": fp})
	if err == nil {
		// Device exists - check ownership
		existingUserID := existingDevice.GetString("user_id")
		if existingUserID != req.UserID {
			if !req.Force {
				fail(w, http.StatusConflict, "ssh key already registered to another user (use force=true to migrate)")
				return
			}
			// Force flag set - migrate key to new user
			log.Printf("migrating device %s from user %s to %s", existingDevice.GetString("device_id"), existingUserID, req.UserID)
		}
		// Update existing device (potentially with new user_id if force=true)
		existingDevice.Set("user_id", req.UserID)
		if req.DeviceName != "" {
			existingDevice.Set("name", req.DeviceName)
		}
		existingDevice.Set("ssh_pubkey", req.SSHPubkeyOpen)
		if err := s.app.Save(existingDevice); err != nil {
			fail(w, http.StatusInternalServerError, "db error")
			return
		}
		deviceID = existingDevice.GetString("device_id")
	} else {
		// Create new device
		deviceRecord := core.NewRecord(devicesCol)
		deviceRecord.Set("device_id", deviceID)
		deviceRecord.Set("user_id", req.UserID)
		deviceRecord.Set("ssh_pubkey", req.SSHPubkeyOpen)
		deviceRecord.Set("ssh_pubkey_fp", fp)
		deviceRecord.Set("name", req.DeviceName)
		if err := s.app.Save(deviceRecord); err != nil {
			fail(w, http.StatusInternalServerError, "db error")
			return
		}
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

	// Check user exists
	usersCol, err := s.app.FindCollectionByNameOrId("sync_users")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	_, err = s.app.FindFirstRecordByFilter(usersCol, "user_id = {:user_id}", map[string]any{"user_id": userID})
	if err != nil {
		fail(w, http.StatusNotFound, "unknown user_id")
		return
	}

	chID := randHex(16)
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		fail(w, http.StatusInternalServerError, "rng error")
		return
	}
	expires := time.Now().Add(2 * time.Minute).Unix()

	// Create challenge record
	challengesCol, err := s.app.FindCollectionByNameOrId("sync_challenges")
	if err != nil {
		fail(w, http.StatusInternalServerError, "collection not found")
		return
	}

	challengeRecord := core.NewRecord(challengesCol)
	challengeRecord.Set("challenge_id", chID)
	challengeRecord.Set("user_id", userID)
	challengeRecord.Set("challenge", base64.StdEncoding.EncodeToString(challenge)) // Store as base64 in text field
	challengeRecord.Set("expires_at", expires)
	if err := s.app.Save(challengeRecord); err != nil {
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

	// Atomically load and delete challenge to prevent TOCTOU attacks
	challenge, expires, err := s.loadAndDeleteChallenge(req.UserID, req.ChallengeID)
	if err != nil {
		return verifyResp{}, http.StatusNotFound, errors.New("unknown challenge")
	}
	if time.Now().Unix() > expires {
		return verifyResp{}, http.StatusUnauthorized, errors.New("challenge expired")
	}

	sig, err := parseSignature(req.SignatureB64)
	if err != nil {
		return verifyResp{}, http.StatusBadRequest, err
	}

	// Find device that can verify this signature
	deviceID, deviceRecord, err := s.findDeviceForSignature(req.UserID, challenge, sig)
	if err != nil {
		return verifyResp{}, http.StatusUnauthorized, errors.New("signature verification failed")
	}

	// Update last_used_at (non-critical, log on error)
	if deviceRecord != nil {
		deviceRecord.Set("last_used_at", time.Now().Unix())
		if err := s.app.Save(deviceRecord); err != nil {
			log.Printf("update device last_used_at error: %v", err)
		}
	}

	resp, err := s.issueTokenForDevice(req.UserID, deviceID)
	if err != nil {
		return verifyResp{}, http.StatusInternalServerError, errors.New("db error")
	}
	return resp, http.StatusOK, nil
}

func (s *Server) findDeviceForSignature(userID string, challenge []byte, sig *ssh.Signature) (string, *core.Record, error) {
	devicesCol, err := s.app.FindCollectionByNameOrId("sync_devices")
	if err != nil {
		return "", nil, err
	}

	devices, err := s.app.FindRecordsByFilter(devicesCol, "user_id = {:user_id}", "", 100, 0, map[string]any{"user_id": userID})
	if err != nil {
		return "", nil, err
	}

	for _, d := range devices {
		pubKeyStr := d.GetString("ssh_pubkey")
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
		if err != nil {
			continue
		}
		if err := pub.Verify(challenge, sig); err == nil {
			return d.GetString("device_id"), d, nil
		}
	}
	return "", nil, errors.New("no matching device")
}

func (s *Server) issueTokenForDevice(userID, deviceID string) (verifyResp, error) {
	token := "sv_" + randHex(32)
	tokenHash := hashToken(token)
	exp := time.Now().Add(12 * time.Hour).Unix()

	tokensCol, err := s.app.FindCollectionByNameOrId("sync_tokens")
	if err != nil {
		return verifyResp{}, err
	}

	tokenRecord := core.NewRecord(tokensCol)
	tokenRecord.Set("token_hash", tokenHash)
	tokenRecord.Set("user_id", userID)
	tokenRecord.Set("device_id", deviceID)
	tokenRecord.Set("expires_at", exp)
	if err := s.app.Save(tokenRecord); err != nil {
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

	// Try JWT first (PocketBase auth)
	if info, err := s.authUserJWT(raw); err == nil {
		return info, nil
	}

	// Fall back to SSH token (legacy)
	return s.authUserSSH(raw)
}

func (s *Server) authUserJWT(token string) (authInfo, error) {
	// Use PocketBase's built-in token verification
	// This works for auth tokens generated by NewAuthToken() or NewStaticAuthToken()
	userRecord, err := s.app.FindAuthRecordByToken(token, "")
	if err != nil {
		return authInfo{}, errors.New("invalid token")
	}

	// JWT tokens don't have device_id - use empty string
	return authInfo{
		userID:   userRecord.Id,
		deviceID: "",
	}, nil
}

func (s *Server) authUserSSH(raw string) (authInfo, error) {
	th := hashToken(raw)

	tokensCol, err := s.app.FindCollectionByNameOrId("sync_tokens")
	if err != nil {
		return authInfo{}, errors.New("db error")
	}

	tokenRecord, err := s.app.FindFirstRecordByFilter(tokensCol, "token_hash = {:token_hash}", map[string]any{"token_hash": th})
	if err != nil {
		return authInfo{}, errors.New("invalid token")
	}

	exp := tokenRecord.GetInt("expires_at")
	if time.Now().Unix() > int64(exp) {
		return authInfo{}, errors.New("token expired")
	}
	return authInfo{
		userID:   tokenRecord.GetString("user_id"),
		deviceID: tokenRecord.GetString("device_id"),
	}, nil
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

		// Insert change within transaction to prevent seq race condition
		err := s.app.RunInTransaction(func(txApp core.App) error {
			changesCol, err := txApp.FindCollectionByNameOrId("sync_changes")
			if err != nil {
				return errors.New("collection not found")
			}

			// Check if change already exists (idempotency)
			_, err = txApp.FindFirstRecordByFilter(changesCol, "user_id = {:user_id} && change_id = {:change_id}",
				map[string]any{"user_id": req.UserID, "change_id": it.ChangeID})
			if err == nil {
				// Already exists, skip (will be acked outside transaction)
				return nil
			}

			// Get next seq number within transaction
			seq, err := getNextSeqTx(txApp, changesCol, req.UserID)
			if err != nil {
				return err
			}

			changeRecord := core.NewRecord(changesCol)
			changeRecord.Set("seq", seq)
			changeRecord.Set("user_id", req.UserID)
			changeRecord.Set("change_id", it.ChangeID)
			changeRecord.Set("device_id", deviceID)
			changeRecord.Set("entity", it.Entity)
			changeRecord.Set("ts", ts)
			changeRecord.Set("nonce_b64", it.Env.NonceB64)
			changeRecord.Set("ct_b64", it.Env.CTB64)
			return txApp.Save(changeRecord)
		})
		if err != nil {
			return nil, errors.New("db error")
		}
		ack = append(ack, it.ChangeID)
	}

	if len(ack) > 0 {
		if err := s.pbClient.IncrementUsage(ctx, req.UserID, len(ack)); err != nil {
			log.Printf("pocketbase usage update failed: %v", err)
		}
	}
	return ack, nil
}

// getNextSeqTx returns the next sequence number within a transaction.
// This ensures atomic read-and-increment to prevent race conditions.
//
//nolint:unparam // Error return kept for API consistency; may be used in future.
func getNextSeqTx(txApp core.App, changesCol *core.Collection, userID string) (int64, error) {
	// Find max seq for this user
	records, err := txApp.FindRecordsByFilter(changesCol, "user_id = {:user_id}", "-seq", 1, 0, map[string]any{"user_id": userID})
	if err != nil {
		// If query fails, start at 1 (safe default for new users)
		return 1, nil //nolint:nilerr // Starting at seq 1 is safe even on query error.
	}
	if len(records) == 0 {
		return 1, nil
	}
	return int64(records[0].GetInt("seq")) + 1, nil
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

//nolint:unparam // ctx reserved for future use (e.g., cancellation).
func (s *Server) queryChanges(_ context.Context, userID string, since int64) ([]pullItem, error) {
	changesCol, err := s.app.FindCollectionByNameOrId("sync_changes")
	if err != nil {
		return nil, err
	}

	records, err := s.app.FindRecordsByFilter(changesCol, "user_id = {:user_id} && seq > {:since}", "seq", 500, 0,
		map[string]any{"user_id": userID, "since": since})
	if err != nil {
		return nil, err
	}

	items := make([]pullItem, len(records))
	for i, r := range records {
		items[i] = pullItem{
			Seq:      int64(r.GetInt("seq")),
			ChangeID: r.GetString("change_id"),
			DeviceID: r.GetString("device_id"),
			Entity:   r.GetString("entity"),
			TS:       int64(r.GetInt("ts")),
			Env:      envelope{NonceB64: r.GetString("nonce_b64"), CTB64: r.GetString("ct_b64")},
		}
	}
	return items, nil
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

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func initPocketBaseClient() pbclient.Client {
	base := strings.TrimSpace(os.Getenv("POCKETBASE_URL"))
	token := strings.TrimSpace(os.Getenv("POCKETBASE_ADMIN_TOKEN"))
	if base == "" || token == "" {
		return pbclient.NoopClient{}
	}
	return &pbclient.HTTPClient{
		BaseURL: base,
		Token:   token,
	}
}

// loadAndDeleteChallenge atomically finds and deletes a challenge in a transaction.
// This prevents TOCTOU attacks where two requests could use the same challenge.
// Returns challenge bytes and expiry. The challenge is deleted regardless of verification outcome.
func (s *Server) loadAndDeleteChallenge(userID, challengeID string) ([]byte, int64, error) {
	var challenge []byte
	var expires int64

	err := s.app.RunInTransaction(func(txApp core.App) error {
		challengesCol, err := txApp.FindCollectionByNameOrId("sync_challenges")
		if err != nil {
			return err
		}

		record, err := txApp.FindFirstRecordByFilter(challengesCol, "challenge_id = {:challenge_id} && user_id = {:user_id}",
			map[string]any{"challenge_id": challengeID, "user_id": userID})
		if err != nil {
			return err
		}

		// Challenge is stored as base64 in text field
		challengeB64 := record.GetString("challenge")
		challenge, err = base64.StdEncoding.DecodeString(challengeB64)
		if err != nil {
			return err
		}

		expires = int64(record.GetInt("expires_at"))

		// Delete the challenge atomically to prevent reuse
		return txApp.Delete(record)
	})

	if err != nil {
		return nil, 0, err
	}
	return challenge, expires, nil
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

// snapshotInfo is used by pull endpoint to return snapshot data.
type snapshotInfo struct {
	SnapshotID string   `json:"snapshot_id"`
	MinSeq     int64    `json:"min_seq"`
	CreatedAt  int64    `json:"created_at"`
	Env        envelope `json:"env"`
}
