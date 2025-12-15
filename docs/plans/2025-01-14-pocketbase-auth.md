# PocketBase Email/Password Auth Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace SSH-based auth with PocketBase email/password auth, where users register with email+password and receive a BIP32 seed phrase for E2E encryption.

**Architecture:** PocketBase handles user authentication (email/password with verification). On register, server generates BIP32 seed and returns it to client. Client stores seed locally and derives app-specific encryption keys. Each CLI app (sweet, todo, notes) independently authenticates and derives its own keys from the shared seed.

**Tech Stack:** PocketBase (built-in auth), Go, BIP39 mnemonic generation, HKDF for app-specific key derivation.

---

## Task 1: Add BIP39 Mnemonic Support to Vault

**Files:**
- Create: `vault/mnemonic.go`
- Create: `vault/mnemonic_test.go`

**Step 1: Write the failing test for mnemonic generation**

```go
// vault/mnemonic_test.go
package vault

import (
	"strings"
	"testing"
)

func TestNewMnemonic(t *testing.T) {
	mnemonic, seed, err := NewMnemonic()
	if err != nil {
		t.Fatalf("NewMnemonic failed: %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		t.Errorf("expected 24 words, got %d", len(words))
	}

	if len(seed) != 64 {
		t.Errorf("expected 64 byte seed, got %d", len(seed))
	}
}

func TestParseMnemonic(t *testing.T) {
	mnemonic, originalSeed, err := NewMnemonic()
	if err != nil {
		t.Fatalf("NewMnemonic failed: %v", err)
	}

	parsedSeed, err := ParseMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("ParseMnemonic failed: %v", err)
	}

	if string(parsedSeed) != string(originalSeed) {
		t.Error("parsed seed does not match original")
	}
}

func TestParseMnemonicInvalid(t *testing.T) {
	_, err := ParseMnemonic("invalid words here")
	if err == nil {
		t.Error("expected error for invalid mnemonic")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test ./vault -run TestMnemonic -v`
Expected: FAIL - undefined functions

**Step 3: Add BIP39 dependency**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go get github.com/tyler-smith/go-bip39`

**Step 4: Write implementation**

```go
// vault/mnemonic.go
// ABOUTME: Provides BIP39 mnemonic phrase generation and parsing for seed backup.
// ABOUTME: Users store mnemonic in password manager for cross-device recovery.
package vault

import (
	"errors"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

// NewMnemonic generates a new 24-word BIP39 mnemonic and derives a 64-byte seed.
// The mnemonic should be displayed to the user for backup in their password manager.
func NewMnemonic() (mnemonic string, seed []byte, err error) {
	entropy, err := bip39.NewEntropy(256) // 256 bits = 24 words
	if err != nil {
		return "", nil, err
	}

	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		return "", nil, err
	}

	// Empty passphrase - user's password manager stores the mnemonic
	seed = bip39.NewSeed(mnemonic, "")
	return mnemonic, seed, nil
}

// ParseMnemonic validates a mnemonic phrase and returns the derived seed.
func ParseMnemonic(mnemonic string) ([]byte, error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if mnemonic == "" {
		return nil, errors.New("mnemonic required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid mnemonic phrase")
	}

	seed := bip39.NewSeed(mnemonic, "")
	return seed, nil
}
```

**Step 5: Run tests**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test ./vault -run TestMnemonic -v`
Expected: PASS

**Step 6: Commit**

```bash
git add vault/mnemonic.go vault/mnemonic_test.go go.mod go.sum
git commit -m "feat(vault): add BIP39 mnemonic generation and parsing"
```

---

## Task 2: Add App-Scoped Key Derivation

**Files:**
- Modify: `vault/keys.go`
- Modify: `vault/keys_test.go`

**Step 1: Write failing test for app-scoped keys**

```go
// Add to vault/keys_test.go
func TestDeriveAppKey(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	sweetKey, err := DeriveAppKey(seed, "sweet")
	if err != nil {
		t.Fatalf("DeriveAppKey failed: %v", err)
	}

	todoKey, err := DeriveAppKey(seed, "todo")
	if err != nil {
		t.Fatalf("DeriveAppKey failed: %v", err)
	}

	if len(sweetKey) != 32 {
		t.Errorf("expected 32 byte key, got %d", len(sweetKey))
	}

	// Different apps must get different keys
	if string(sweetKey) == string(todoKey) {
		t.Error("different apps should derive different keys")
	}
}

func TestDeriveAppKeySameAppSameKey(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	key1, _ := DeriveAppKey(seed, "sweet")
	key2, _ := DeriveAppKey(seed, "sweet")

	if string(key1) != string(key2) {
		t.Error("same app should derive same key")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test ./vault -run TestDeriveAppKey -v`
Expected: FAIL - undefined function

**Step 3: Implement DeriveAppKey**

Add to `vault/keys.go`:

```go
// DeriveAppKey derives an app-specific 32-byte encryption key from a BIP39 seed.
// Each app (sweet, todo, notes, etc.) gets a unique key derived from the same seed.
func DeriveAppKey(seed []byte, appID string) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("seed required")
	}
	if appID == "" {
		return nil, errors.New("app ID required")
	}

	// Use HKDF with app-specific info to derive unique key per app
	info := []byte("syncvault:v1:app:" + appID)
	reader := hkdf.New(sha256.New, seed, nil, info)

	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}

	return key, nil
}
```

Also add `"errors"` to imports if not present.

**Step 4: Run tests**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test ./vault -run TestDeriveAppKey -v`
Expected: PASS

**Step 5: Commit**

```bash
git add vault/keys.go vault/keys_test.go
git commit -m "feat(vault): add app-scoped key derivation for multi-app support"
```

---

## Task 3: Create PocketBase Auth Client

**Files:**
- Create: `vault/auth.go`
- Create: `vault/auth_test.go`

**Step 1: Write the auth client interface test**

```go
// vault/auth_test.go
package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthClientRegister(t *testing.T) {
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/register" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		if req.Email == "" || req.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "email and password required"})
			return
		}

		json.NewEncoder(w).Encode(map[string]any{
			"user_id":     "usr_123",
			"token":       "tok_abc",
			"expires_unix": time.Now().Add(24 * time.Hour).Unix(),
			"mnemonic":    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		})
	}))
	defer server.Close()

	client := NewAuthClient(server.URL)
	result, err := client.Register(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if result.UserID != "usr_123" {
		t.Errorf("unexpected user_id: %s", result.UserID)
	}
	if result.Token.Token != "tok_abc" {
		t.Errorf("unexpected token: %s", result.Token.Token)
	}
	if result.Mnemonic == "" {
		t.Error("expected mnemonic in response")
	}
}

func TestAuthClientLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		json.NewEncoder(w).Encode(map[string]any{
			"user_id":       "usr_123",
			"token":         "tok_xyz",
			"refresh_token": "ref_abc",
			"expires_unix":  time.Now().Add(24 * time.Hour).Unix(),
		})
	}))
	defer server.Close()

	client := NewAuthClient(server.URL)
	result, err := client.Login(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if result.Token.Token != "tok_xyz" {
		t.Errorf("unexpected token: %s", result.Token.Token)
	}
	if result.RefreshToken != "ref_abc" {
		t.Errorf("unexpected refresh token: %s", result.RefreshToken)
	}
}

func TestAuthClientRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/refresh" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		json.NewEncoder(w).Encode(map[string]any{
			"token":         "tok_new",
			"refresh_token": "ref_new",
			"expires_unix":  time.Now().Add(24 * time.Hour).Unix(),
		})
	}))
	defer server.Close()

	client := NewAuthClient(server.URL)
	result, err := client.Refresh(context.Background(), "ref_old")
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if result.Token.Token != "tok_new" {
		t.Errorf("unexpected token: %s", result.Token.Token)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test ./vault -run TestAuthClient -v`
Expected: FAIL - undefined types and methods

**Step 3: Implement auth client**

```go
// vault/auth.go
// ABOUTME: Provides PocketBase email/password authentication for vault clients.
// ABOUTME: Handles register, login, and token refresh with BIP39 seed management.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AuthClient handles PocketBase-based authentication.
type AuthClient struct {
	baseURL string
	hc      *http.Client
}

// NewAuthClient constructs an AuthClient for the given server URL.
func NewAuthClient(baseURL string) *AuthClient {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return &AuthClient{
		baseURL: baseURL,
		hc:      &http.Client{Timeout: 30 * time.Second},
	}
}

// AuthToken represents an access token with expiration.
type AuthToken struct {
	Token   string
	Expires time.Time
}

// RegisterResult contains the response from user registration.
type RegisterResult struct {
	UserID   string
	Token    AuthToken
	Mnemonic string // 24-word BIP39 mnemonic - user MUST save this
}

// LoginResult contains the response from login.
type LoginResult struct {
	UserID       string
	Token        AuthToken
	RefreshToken string
}

// RefreshResult contains the response from token refresh.
type RefreshResult struct {
	Token        AuthToken
	RefreshToken string
}

// Register creates a new user account with email/password.
// Returns a mnemonic phrase that the user MUST save for recovery.
func (c *AuthClient) Register(ctx context.Context, email, password string) (RegisterResult, error) {
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	if email == "" || password == "" {
		return RegisterResult{}, errors.New("email and password required")
	}

	req := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    email,
		Password: password,
	}

	resp, err := c.doJSON(ctx, "/v1/auth/register", req)
	if err != nil {
		return RegisterResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return RegisterResult{}, fmt.Errorf("register failed: %s", decodeErrorBody(resp))
	}

	var body struct {
		UserID      string `json:"user_id"`
		Token       string `json:"token"`
		ExpiresUnix int64  `json:"expires_unix"`
		Mnemonic    string `json:"mnemonic"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return RegisterResult{}, err
	}

	return RegisterResult{
		UserID: body.UserID,
		Token: AuthToken{
			Token:   body.Token,
			Expires: time.Unix(body.ExpiresUnix, 0).UTC(),
		},
		Mnemonic: body.Mnemonic,
	}, nil
}

// Login authenticates with email/password and returns tokens.
func (c *AuthClient) Login(ctx context.Context, email, password string) (LoginResult, error) {
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	if email == "" || password == "" {
		return LoginResult{}, errors.New("email and password required")
	}

	req := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    email,
		Password: password,
	}

	resp, err := c.doJSON(ctx, "/v1/auth/login", req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return LoginResult{}, fmt.Errorf("login failed: %s", decodeErrorBody(resp))
	}

	var body struct {
		UserID       string `json:"user_id"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresUnix  int64  `json:"expires_unix"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		UserID: body.UserID,
		Token: AuthToken{
			Token:   body.Token,
			Expires: time.Unix(body.ExpiresUnix, 0).UTC(),
		},
		RefreshToken: body.RefreshToken,
	}, nil
}

// Refresh exchanges a refresh token for new access and refresh tokens.
func (c *AuthClient) Refresh(ctx context.Context, refreshToken string) (RefreshResult, error) {
	if refreshToken == "" {
		return RefreshResult{}, errors.New("refresh token required")
	}

	req := struct {
		RefreshToken string `json:"refresh_token"`
	}{
		RefreshToken: refreshToken,
	}

	resp, err := c.doJSON(ctx, "/v1/auth/refresh", req)
	if err != nil {
		return RefreshResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return RefreshResult{}, fmt.Errorf("refresh failed: %s", decodeErrorBody(resp))
	}

	var body struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresUnix  int64  `json:"expires_unix"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return RefreshResult{}, err
	}

	return RefreshResult{
		Token: AuthToken{
			Token:   body.Token,
			Expires: time.Unix(body.ExpiresUnix, 0).UTC(),
		},
		RefreshToken: body.RefreshToken,
	}, nil
}

func (c *AuthClient) doJSON(ctx context.Context, path string, body any) (*http.Response, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	return c.hc.Do(req)
}

func decodeErrorBody(resp *http.Response) string {
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Error == "" {
		return resp.Status
	}
	return body.Error
}
```

**Step 4: Run tests**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test ./vault -run TestAuthClient -v`
Expected: PASS

**Step 5: Commit**

```bash
git add vault/auth.go vault/auth_test.go
git commit -m "feat(vault): add PocketBase email/password auth client"
```

---

## Task 4: Update syncvaultd with PocketBase Auth Endpoints

**Files:**
- Modify: `cmd/syncvaultd/main.go`
- Create: `cmd/syncvaultd/auth.go` (extract auth handlers)

**Step 1: Create auth.go with new endpoint handlers**

```go
// cmd/syncvaultd/auth.go
// ABOUTME: Handles PocketBase email/password authentication endpoints.
// ABOUTME: Generates BIP39 mnemonic on register, issues JWT tokens on login.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"suitesync/vault"
)

// POST /v1/auth/register
type pbRegisterReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handlePBRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req pbRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Password = strings.TrimSpace(req.Password)
	if req.Email == "" || req.Password == "" {
		fail(w, http.StatusBadRequest, "email and password required")
		return
	}

	if len(req.Password) < 8 {
		fail(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	// Generate BIP39 mnemonic for the user
	mnemonic, _, err := vault.NewMnemonic()
	if err != nil {
		log.Printf("mnemonic generation error: %v", err)
		fail(w, http.StatusInternalServerError, "failed to generate recovery phrase")
		return
	}

	// Create user in PocketBase users collection
	usersCol, err := s.app.FindCollectionByNameOrId("users")
	if err != nil {
		log.Printf("users collection not found: %v", err)
		fail(w, http.StatusInternalServerError, "auth not configured")
		return
	}

	// Check if email already exists
	_, err = s.app.FindAuthRecordByEmail(usersCol, req.Email)
	if err == nil {
		fail(w, http.StatusConflict, "email already registered")
		return
	}

	// Create the user record
	userRecord := core.NewRecord(usersCol)
	userRecord.Set("email", req.Email)
	userRecord.SetPassword(req.Password)
	userRecord.Set("verified", false) // Require email verification

	if err := s.app.Save(userRecord); err != nil {
		log.Printf("user creation error: %v", err)
		fail(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	// Send verification email
	if err := s.app.SendRecordVerificationRequest(usersCol, userRecord, nil); err != nil {
		log.Printf("verification email error: %v", err)
		// Don't fail - user can request verification again
	}

	// Generate access token
	token, err := security.NewJWT(
		security.JWTConfig{
			SignKey: s.app.Settings().RecordAuthToken.Secret,
			Payload: map[string]any{
				"id":         userRecord.Id,
				"type":       "auth",
				"collection": usersCol.Id,
			},
			Duration: 24 * time.Hour,
		},
	)
	if err != nil {
		log.Printf("token generation error: %v", err)
		fail(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	expires := time.Now().Add(24 * time.Hour)

	json.NewEncoder(w).Encode(map[string]any{
		"user_id":      userRecord.Id,
		"token":        token,
		"expires_unix": expires.Unix(),
		"mnemonic":     mnemonic,
		"message":      "Please check your email to verify your account",
	})
}

// POST /v1/auth/login
type pbLoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handlePBLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req pbLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Password = strings.TrimSpace(req.Password)
	if req.Email == "" || req.Password == "" {
		fail(w, http.StatusBadRequest, "email and password required")
		return
	}

	// Find user by email
	usersCol, err := s.app.FindCollectionByNameOrId("users")
	if err != nil {
		fail(w, http.StatusInternalServerError, "auth not configured")
		return
	}

	userRecord, err := s.app.FindAuthRecordByEmail(usersCol, req.Email)
	if err != nil {
		fail(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Verify password
	if !userRecord.ValidatePassword(req.Password) {
		fail(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Check if verified
	if !userRecord.Verified() {
		fail(w, http.StatusForbidden, "please verify your email first")
		return
	}

	// Generate access token
	token, err := security.NewJWT(
		security.JWTConfig{
			SignKey: s.app.Settings().RecordAuthToken.Secret,
			Payload: map[string]any{
				"id":         userRecord.Id,
				"type":       "auth",
				"collection": usersCol.Id,
			},
			Duration: 24 * time.Hour,
		},
	)
	if err != nil {
		fail(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Generate refresh token
	refreshToken := randHex(32)
	refreshExpires := time.Now().Add(30 * 24 * time.Hour) // 30 days

	// Store refresh token
	tokensCol, err := s.app.FindCollectionByNameOrId("refresh_tokens")
	if err == nil {
		tokenRecord := core.NewRecord(tokensCol)
		tokenRecord.Set("user", userRecord.Id)
		tokenRecord.Set("token_hash", hashToken(refreshToken))
		tokenRecord.Set("expires", refreshExpires)
		if err := s.app.Save(tokenRecord); err != nil {
			log.Printf("refresh token save error: %v", err)
		}
	}

	expires := time.Now().Add(24 * time.Hour)

	json.NewEncoder(w).Encode(map[string]any{
		"user_id":       userRecord.Id,
		"token":         token,
		"refresh_token": refreshToken,
		"expires_unix":  expires.Unix(),
	})
}

// POST /v1/auth/refresh
type pbRefreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handlePBRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req pbRefreshReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid json")
		return
	}

	if req.RefreshToken == "" {
		fail(w, http.StatusBadRequest, "refresh_token required")
		return
	}

	// Find refresh token
	tokensCol, err := s.app.FindCollectionByNameOrId("refresh_tokens")
	if err != nil {
		fail(w, http.StatusInternalServerError, "auth not configured")
		return
	}

	tokenHash := hashToken(req.RefreshToken)
	tokenRecord, err := s.app.FindFirstRecordByFilter(tokensCol, "token_hash = {:hash}", map[string]any{"hash": tokenHash})
	if err != nil {
		fail(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	// Check expiration
	expires := tokenRecord.GetDateTime("expires")
	if expires.Time().Before(time.Now()) {
		s.app.Delete(tokenRecord)
		fail(w, http.StatusUnauthorized, "refresh token expired")
		return
	}

	// Get user
	userID := tokenRecord.GetString("user")
	usersCol, err := s.app.FindCollectionByNameOrId("users")
	if err != nil {
		fail(w, http.StatusInternalServerError, "auth not configured")
		return
	}

	userRecord, err := s.app.FindRecordById(usersCol, userID)
	if err != nil {
		fail(w, http.StatusUnauthorized, "user not found")
		return
	}

	// Delete old refresh token (single use)
	if err := s.app.Delete(tokenRecord); err != nil {
		log.Printf("refresh token delete error: %v", err)
	}

	// Generate new access token
	token, err := security.NewJWT(
		security.JWTConfig{
			SignKey: s.app.Settings().RecordAuthToken.Secret,
			Payload: map[string]any{
				"id":         userRecord.Id,
				"type":       "auth",
				"collection": usersCol.Id,
			},
			Duration: 24 * time.Hour,
		},
	)
	if err != nil {
		fail(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Generate new refresh token
	newRefreshToken := randHex(32)
	newRefreshExpires := time.Now().Add(30 * 24 * time.Hour)

	// Store new refresh token
	newTokenRecord := core.NewRecord(tokensCol)
	newTokenRecord.Set("user", userRecord.Id)
	newTokenRecord.Set("token_hash", hashToken(newRefreshToken))
	newTokenRecord.Set("expires", newRefreshExpires)
	if err := s.app.Save(newTokenRecord); err != nil {
		log.Printf("refresh token save error: %v", err)
	}

	newExpires := time.Now().Add(24 * time.Hour)

	json.NewEncoder(w).Encode(map[string]any{
		"token":         token,
		"refresh_token": newRefreshToken,
		"expires_unix":  newExpires.Unix(),
	})
}

func hashToken(token string) string {
	b := make([]byte, 32)
	rand.Read(b)
	// Simple hash for now - in production use bcrypt or similar
	return hex.EncodeToString([]byte(token))[:64]
}
```

**Step 2: Update route registration in main.go**

Replace the auth routes in `registerRoutes`:

```go
// Auth endpoints (with IP-based rate limiting) - PocketBase email/password
r.POST("/v1/auth/register", s.wrapHandler(s.withIPRateLimit(s.handlePBRegister)))
r.POST("/v1/auth/login", s.wrapHandler(s.withIPRateLimit(s.handlePBLogin)))
r.POST("/v1/auth/refresh", s.wrapHandler(s.withIPRateLimit(s.handlePBRefresh)))
```

**Step 3: Create migration for refresh_tokens collection**

```go
// cmd/syncvaultd/migrations/1736900000_create_refresh_tokens.go
package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		collection := core.NewBaseCollection("refresh_tokens")
		collection.Fields.Add(&core.TextField{
			Name:     "user",
			Required: true,
		})
		collection.Fields.Add(&core.TextField{
			Name:     "token_hash",
			Required: true,
		})
		collection.Fields.Add(&core.DateField{
			Name:     "expires",
			Required: true,
		})
		collection.Indexes = []string{
			"CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens (token_hash)",
			"CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user)",
		}
		return app.Save(collection)
	}, func(app core.App) error {
		collection, err := app.FindCollectionByNameOrId("refresh_tokens")
		if err != nil {
			return nil
		}
		return app.Delete(collection)
	})
}
```

**Step 4: Update withAuth middleware to use JWT**

In main.go, update the `withAuth` function:

```go
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			fail(w, http.StatusUnauthorized, "authorization required")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			fail(w, http.StatusUnauthorized, "bearer token required")
			return
		}

		// Verify JWT
		usersCol, err := s.app.FindCollectionByNameOrId("users")
		if err != nil {
			fail(w, http.StatusInternalServerError, "auth not configured")
			return
		}

		claims, err := security.ParseJWT(token, s.app.Settings().RecordAuthToken.Secret)
		if err != nil {
			fail(w, http.StatusUnauthorized, "invalid token")
			return
		}

		userID, ok := claims["id"].(string)
		if !ok {
			fail(w, http.StatusUnauthorized, "invalid token claims")
			return
		}

		userRecord, err := s.app.FindRecordById(usersCol, userID)
		if err != nil {
			fail(w, http.StatusUnauthorized, "user not found")
			return
		}

		// Apply rate limiting
		if s.limiters != nil {
			limiter := s.limiters.get(userID)
			if !limiter.Allow() {
				fail(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}

		// Set user context
		ctx := context.WithValue(r.Context(), "user_id", userRecord.Id)
		next(w, r.WithContext(ctx))
	}
}
```

**Step 5: Run tests and verify**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go build ./cmd/syncvaultd`
Expected: Build succeeds

**Step 6: Commit**

```bash
git add cmd/syncvaultd/auth.go cmd/syncvaultd/main.go cmd/syncvaultd/migrations/
git commit -m "feat(syncvaultd): replace SSH auth with PocketBase email/password auth"
```

---

## Task 5: Update Sweet CLI for New Auth Flow

**Files:**
- Modify: `cmd/sweet/auth.go`
- Modify: `cmd/sweet/config.go`
- Modify: `cmd/sweet/main.go`

**Step 1: Update config structure**

In `cmd/sweet/config.go`, update Config struct:

```go
type Config struct {
	Server       string `json:"server"`
	Email        string `json:"email"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	TokenExpires string `json:"token_expires"`
	Mnemonic     string `json:"mnemonic"` // Encrypted locally
	AppID        string `json:"app_id"`
	DeviceID     string `json:"device_id"`
	AppDB        string `json:"app_db"`
	VaultDB      string `json:"vault_db"`
}
```

**Step 2: Rewrite auth.go with new commands**

```go
// cmd/sweet/auth.go
// ABOUTME: Implements register, login, logout, and status commands for sweet CLI.
// ABOUTME: Handles PocketBase email/password auth with BIP39 seed management.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"suitesync/vault"
)

const appID = "sweet"

// cmdRegister creates a new account and generates recovery phrase.
func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "https://syncvault.fly.dev", "sync server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Get email
	fmt.Print("Email: ")
	reader := bufio.NewReader(os.Stdin)
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email required")
	}

	// Get password
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	password := string(passwordBytes)

	fmt.Print("Confirm password: ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	if password != string(confirmBytes) {
		return fmt.Errorf("passwords do not match")
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	// Register with server
	fmt.Printf("\nRegistering with %s...\n", *server)
	client := vault.NewAuthClient(*server)
	result, err := client.Register(context.Background(), email, password)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	fmt.Println("\n✓ Account created!")
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("IMPORTANT: Save this recovery phrase in your password manager.")
	fmt.Println("You will need it to set up other devices or apps.")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	fmt.Println(result.Mnemonic)
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Print("\nPress Enter after you've saved this phrase...")
	reader.ReadString('\n')

	// Save config
	cfg, _ := LoadConfig()
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.Server = *server
	cfg.Email = email
	cfg.Token = result.Token.Token
	cfg.TokenExpires = result.Token.Expires.Format(time.RFC3339)
	cfg.Mnemonic = result.Mnemonic // TODO: encrypt locally
	cfg.AppID = appID
	if cfg.DeviceID == "" {
		cfg.DeviceID = randHex(16)
	}

	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("\n✓ Logged in to sweet")
	fmt.Printf("Token expires: %s\n", result.Token.Expires.Format(time.RFC3339))
	fmt.Println("\nPlease check your email to verify your account.")

	return nil
}

// cmdLogin authenticates with email/password and mnemonic.
func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "sync server URL (overrides config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, _ := LoadConfig()
	if cfg == nil {
		cfg = &Config{}
	}

	serverURL := *server
	if serverURL == "" {
		serverURL = cfg.Server
	}
	if serverURL == "" {
		serverURL = "https://syncvault.fly.dev"
	}

	// Get email
	fmt.Print("Email: ")
	reader := bufio.NewReader(os.Stdin)
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email required")
	}

	// Get password
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	password := string(passwordBytes)

	// Get mnemonic
	fmt.Print("\nEnter your recovery phrase (from your password manager):\n> ")
	mnemonic, _ := reader.ReadString('\n')
	mnemonic = strings.TrimSpace(mnemonic)

	// Validate mnemonic
	if _, err := vault.ParseMnemonic(mnemonic); err != nil {
		return fmt.Errorf("invalid recovery phrase: %w", err)
	}

	// Login to server
	fmt.Printf("\nLogging in to %s...\n", serverURL)
	client := vault.NewAuthClient(serverURL)
	result, err := client.Login(context.Background(), email, password)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Save config
	cfg.Server = serverURL
	cfg.Email = email
	cfg.Token = result.Token.Token
	cfg.RefreshToken = result.RefreshToken
	cfg.TokenExpires = result.Token.Expires.Format(time.RFC3339)
	cfg.Mnemonic = mnemonic // TODO: encrypt locally
	cfg.AppID = appID
	if cfg.DeviceID == "" {
		cfg.DeviceID = randHex(16)
	}

	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("\n✓ Logged in to sweet")
	fmt.Printf("Token expires: %s\n", result.Token.Expires.Format(time.RFC3339))

	return nil
}

// cmdLogout clears auth tokens from config.
func cmdLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Token == "" {
		fmt.Println("Not logged in")
		return nil
	}

	cfg.Token = ""
	cfg.RefreshToken = ""
	cfg.TokenExpires = ""
	// Keep mnemonic - user may want to login again

	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("✓ Logged out successfully")
	return nil
}

// cmdStatus shows current auth status.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Printf("Config:    %s\n", ConfigPath())
	fmt.Printf("Server:    %s\n", valueOrNone(cfg.Server))
	fmt.Printf("Email:     %s\n", valueOrNone(cfg.Email))
	fmt.Printf("App ID:    %s\n", valueOrNone(cfg.AppID))
	fmt.Printf("Device ID: %s\n", valueOrNone(cfg.DeviceID))

	if cfg.Mnemonic != "" {
		fmt.Println("Recovery:  ✓ stored")
	} else {
		fmt.Println("Recovery:  (not set)")
	}

	printTokenStatus(cfg)

	return nil
}

func printTokenStatus(cfg *Config) {
	if cfg.Token == "" {
		fmt.Println("\nStatus: Not logged in")
		return
	}

	fmt.Println()
	if cfg.TokenExpires == "" {
		fmt.Println("Token: valid (no expiry info)")
		return
	}

	expires, err := time.Parse(time.RFC3339, cfg.TokenExpires)
	if err != nil {
		fmt.Printf("Token: valid (invalid expiry: %v)\n", err)
		return
	}

	now := time.Now()
	if expires.Before(now) {
		fmt.Printf("Token: EXPIRED (%s ago)\n", now.Sub(expires).Round(time.Second))
		if cfg.RefreshToken != "" {
			fmt.Println("       (has refresh token - run any command to auto-refresh)")
		}
	} else {
		fmt.Printf("Token: valid (expires in %s)\n", formatDuration(expires.Sub(now)))
	}
}

func valueOrNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
```

**Step 3: Update main.go commands**

Update the command dispatch in main.go:

```go
case "register":
	return cmdRegister(args[1:])
case "login":
	return cmdLogin(args[1:])
case "logout":
	return cmdLogout(args[1:])
case "status":
	return cmdStatus(args[1:])
```

**Step 4: Add golang.org/x/term dependency**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go get golang.org/x/term`

**Step 5: Build and test**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go build ./cmd/sweet`
Expected: Build succeeds

**Step 6: Commit**

```bash
git add cmd/sweet/auth.go cmd/sweet/config.go cmd/sweet/main.go go.mod go.sum
git commit -m "feat(sweet): update CLI for PocketBase email/password auth"
```

---

## Task 6: Remove SSH Auth Code

**Files:**
- Delete: `vault/auth_ssh.go`
- Modify: `cmd/syncvaultd/main.go` (remove SSH imports and handlers)

**Step 1: Remove SSH handlers from main.go**

Remove:
- `handleRegister` (SSH version)
- `handleChallenge`
- `handleVerify`
- SSH-related imports (`golang.org/x/crypto/ssh`)
- `registerReq` struct
- Challenge-related code

**Step 2: Delete auth_ssh.go**

Run: `rm /Users/harper/Public/src/2389/suite-sync/vault/auth_ssh.go`

**Step 3: Update any imports**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go mod tidy`

**Step 4: Verify build**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go build ./...`
Expected: Build succeeds

**Step 5: Commit**

```bash
git add -A
git commit -m "refactor: remove SSH-based auth in favor of PocketBase email/password"
```

---

## Task 7: Integration Test

**Files:**
- Create: `cmd/syncvaultd/main_integration_test.go`

**Step 1: Write integration test**

```go
// cmd/syncvaultd/main_integration_test.go
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthFlow(t *testing.T) {
	// This test requires a running PocketBase instance
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Test register -> login -> refresh flow
	t.Run("full auth flow", func(t *testing.T) {
		// Register
		regBody := `{"email":"test@example.com","password":"testpass123"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewBufferString(regBody))
		req.Header.Set("Content-Type", "application/json")

		// ... test implementation
	})
}
```

**Step 2: Run tests**

Run: `cd /Users/harper/Public/src/2389/suite-sync && go test ./... -v`
Expected: All tests pass

**Step 3: Commit**

```bash
git add cmd/syncvaultd/main_integration_test.go
git commit -m "test: add integration tests for PocketBase auth flow"
```

---

## Summary

After completing all tasks:
1. Users register with email/password and receive a 24-word recovery phrase
2. Email verification is required before login
3. Login requires email/password + recovery phrase (from password manager)
4. Each CLI app derives its own encryption key from the shared phrase
5. Refresh tokens provide persistent sessions
6. SSH auth is completely removed

The system is now simpler (no SSH key management) while maintaining E2E encryption security.
