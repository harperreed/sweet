// ABOUTME: Handles PocketBase email/password authentication endpoints.
// ABOUTME: Generates BIP39 mnemonic on register, issues JWT tokens on login.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"suitesync/vault"

	"github.com/pocketbase/pocketbase/core"
)

// POST /v1/auth/register.
type pbRegisterReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

//nolint:funlen // Auth registration requires multiple validation and creation steps.
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

	// Generate verification token
	verificationToken, err := userRecord.NewVerificationToken()
	if err != nil {
		log.Printf("verification token error: %v", err)
	}

	// Generate access token (24 hour static auth token)
	token, err := userRecord.NewStaticAuthToken(24 * time.Hour)
	if err != nil {
		log.Printf("token generation error: %v", err)
		fail(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	expires := time.Now().Add(24 * time.Hour)

	// Log verification token for development (in production, send email)
	if verificationToken != "" {
		log.Printf("Verification token for %s: %s", req.Email, verificationToken)
	}

	//nolint:errchkjson // Response encoding errors are not recoverable.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user_id":      userRecord.Id,
		"token":        token,
		"expires_unix": expires.Unix(),
		"mnemonic":     mnemonic,
		"message":      "Please check your email to verify your account",
	})
}

// POST /v1/auth/login.
type pbLoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

//nolint:funlen // Auth login requires validation, password check, and token generation.
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

	// Generate access token (24 hour static auth token)
	token, err := userRecord.NewStaticAuthToken(24 * time.Hour)
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
		tokenRecord.Set("token_hash", hashRefreshToken(refreshToken))
		tokenRecord.Set("expires", refreshExpires)
		if err := s.app.Save(tokenRecord); err != nil {
			log.Printf("refresh token save error: %v", err)
		}
	}

	expires := time.Now().Add(24 * time.Hour)

	//nolint:errchkjson // Response encoding errors are not recoverable.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user_id":       userRecord.Id,
		"token":         token,
		"refresh_token": refreshToken,
		"expires_unix":  expires.Unix(),
	})
}

// POST /v1/auth/refresh.
type pbRefreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

//nolint:funlen // Auth refresh requires token validation, rotation, and new token generation.
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

	tokenHash := hashRefreshToken(req.RefreshToken)
	tokenRecord, err := s.app.FindFirstRecordByFilter(tokensCol, "token_hash = {:hash}", map[string]any{"hash": tokenHash})
	if err != nil {
		fail(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	// Check expiration
	expires := tokenRecord.GetDateTime("expires")
	if expires.Time().Before(time.Now()) {
		_ = s.app.Delete(tokenRecord)
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

	// Generate new access token (24 hour static auth token)
	token, err := userRecord.NewStaticAuthToken(24 * time.Hour)
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
	newTokenRecord.Set("token_hash", hashRefreshToken(newRefreshToken))
	newTokenRecord.Set("expires", newRefreshExpires)
	if err := s.app.Save(newTokenRecord); err != nil {
		log.Printf("refresh token save error: %v", err)
	}

	newExpires := time.Now().Add(24 * time.Hour)

	//nolint:errchkjson // Response encoding errors are not recoverable.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":         token,
		"refresh_token": newRefreshToken,
		"expires_unix":  newExpires.Unix(),
	})
}

// hashRefreshToken creates a SHA-256 hash of the refresh token for storage.
func hashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
