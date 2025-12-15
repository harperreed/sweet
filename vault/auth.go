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

// PBAuthClient handles PocketBase-based authentication.
type PBAuthClient struct {
	baseURL string
	hc      *http.Client
}

// NewPBAuthClient constructs a PBAuthClient for the given server URL.
func NewPBAuthClient(baseURL string) *PBAuthClient {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return &PBAuthClient{
		baseURL: baseURL,
		hc:      &http.Client{Timeout: 30 * time.Second},
	}
}

// PBAuthToken represents an access token with expiration.
type PBAuthToken struct {
	Token   string
	Expires time.Time
}

// RegisterResult contains the response from user registration.
type RegisterResult struct {
	UserID   string
	Token    PBAuthToken
	Mnemonic string // 24-word BIP39 mnemonic - user MUST save this
}

// LoginResult contains the response from login.
type LoginResult struct {
	UserID       string
	Token        PBAuthToken
	RefreshToken string
}

// RefreshResult contains the response from token refresh.
type RefreshResult struct {
	Token        PBAuthToken
	RefreshToken string
}

// Register creates a new user account with email/password.
// Returns a mnemonic phrase that the user MUST save for recovery.
func (c *PBAuthClient) Register(ctx context.Context, email, password string) (RegisterResult, error) {
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
	defer func() { _ = resp.Body.Close() }()

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
		Token: PBAuthToken{
			Token:   body.Token,
			Expires: time.Unix(body.ExpiresUnix, 0).UTC(),
		},
		Mnemonic: body.Mnemonic,
	}, nil
}

// Login authenticates with email/password and returns tokens.
func (c *PBAuthClient) Login(ctx context.Context, email, password string) (LoginResult, error) {
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
	defer func() { _ = resp.Body.Close() }()

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
		Token: PBAuthToken{
			Token:   body.Token,
			Expires: time.Unix(body.ExpiresUnix, 0).UTC(),
		},
		RefreshToken: body.RefreshToken,
	}, nil
}

// Refresh exchanges a refresh token for new access and refresh tokens.
func (c *PBAuthClient) Refresh(ctx context.Context, refreshToken string) (RefreshResult, error) {
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
	defer func() { _ = resp.Body.Close() }()

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
		Token: PBAuthToken{
			Token:   body.Token,
			Expires: time.Unix(body.ExpiresUnix, 0).UTC(),
		},
		RefreshToken: body.RefreshToken,
	}, nil
}

func (c *PBAuthClient) doJSON(ctx context.Context, path string, body any) (*http.Response, error) {
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
