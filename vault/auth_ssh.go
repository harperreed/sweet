package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// AuthClient wraps SSH-based auth endpoints exposed by syncvaultd.
type AuthClient struct {
	baseURL string
	hc      *http.Client
}

// NewAuthClient constructs an AuthClient for the given base URL.
func NewAuthClient(baseURL string) *AuthClient {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return &AuthClient{
		baseURL: baseURL,
		hc:      &http.Client{Timeout: 15 * time.Second},
	}
}

// AuthToken is returned upon successful login.
type AuthToken struct {
	Token   string
	Expires time.Time
}

// Challenge contains challenge bytes issued by server.
type Challenge struct {
	ID      string
	Data    []byte
	Expires time.Time
}

// RegisterWithKeyFile registers (or updates) the SSH public key for userID using keyPath.
func (c *AuthClient) RegisterWithKeyFile(ctx context.Context, userID, keyPath string, passphrase []byte) error {
	signer, err := loadSignerFromPath(keyPath, passphrase)
	if err != nil {
		return err
	}
	return c.registerWithSigner(ctx, userID, signer)
}

// RegisterAuthorizedKey registers an already marshalled authorized-key string.
func (c *AuthClient) RegisterAuthorizedKey(ctx context.Context, userID, authorizedKey string) error {
	authorizedKey = strings.TrimSpace(authorizedKey)
	if authorizedKey == "" {
		return errors.New("authorized key required")
	}
	req := struct {
		UserID        string `json:"user_id"`
		SSHPubkeyOpen string `json:"ssh_pubkey_openssh"`
	}{
		UserID:        userID,
		SSHPubkeyOpen: authorizedKey,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/v1/auth/register", req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register failed: %s", decodeError(resp))
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	return nil
}

// LoginWithKeyFile registers (if autoRegister) and signs challenge with key file.
func (c *AuthClient) LoginWithKeyFile(ctx context.Context, userID, keyPath string, passphrase []byte, autoRegister bool) (AuthToken, error) {
	signer, err := loadSignerFromPath(keyPath, passphrase)
	if err != nil {
		return AuthToken{}, err
	}
	return c.LoginWithSigner(ctx, userID, signer, autoRegister)
}

// LoginWithSigner registers (if requested) and signs challenge with provided signer.
func (c *AuthClient) LoginWithSigner(ctx context.Context, userID string, signer ssh.Signer, autoRegister bool) (AuthToken, error) {
	if signer == nil {
		return AuthToken{}, errors.New("signer required")
	}
	if autoRegister {
		if err := c.registerWithSigner(ctx, userID, signer); err != nil {
			return AuthToken{}, err
		}
	}
	ch, err := c.Challenge(ctx, userID)
	if err != nil {
		return AuthToken{}, err
	}
	sig, err := signer.Sign(rand.Reader, ch.Data)
	if err != nil {
		return AuthToken{}, err
	}
	sigB64 := base64.StdEncoding.EncodeToString(ssh.Marshal(sig))
	return c.Verify(ctx, userID, ch.ID, sigB64)
}

// Challenge fetches a challenge for userID.
func (c *AuthClient) Challenge(ctx context.Context, userID string) (Challenge, error) {
	req := struct {
		UserID string `json:"user_id"`
	}{UserID: userID}
	resp, err := c.doJSON(ctx, http.MethodPost, "/v1/auth/challenge", req)
	if err != nil {
		return Challenge{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Challenge{}, fmt.Errorf("challenge failed: %s", decodeError(resp))
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	var body struct {
		ChallengeID  string `json:"challenge_id"`
		ChallengeB64 string `json:"challenge_b64"`
		ExpiresUnix  int64  `json:"expires_unix"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Challenge{}, err
	}
	data, err := base64.StdEncoding.DecodeString(body.ChallengeB64)
	if err != nil {
		return Challenge{}, err
	}
	return Challenge{
		ID:      body.ChallengeID,
		Data:    data,
		Expires: time.Unix(body.ExpiresUnix, 0).UTC(),
	}, nil
}

// Verify sends signature for challengeID and returns token.
func (c *AuthClient) Verify(ctx context.Context, userID, challengeID, signatureB64 string) (AuthToken, error) {
	req := struct {
		UserID       string `json:"user_id"`
		ChallengeID  string `json:"challenge_id"`
		SignatureB64 string `json:"signature_b64"`
	}{
		UserID:       userID,
		ChallengeID:  challengeID,
		SignatureB64: signatureB64,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/v1/auth/verify", req)
	if err != nil {
		return AuthToken{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return AuthToken{}, fmt.Errorf("verify failed: %s", decodeError(resp))
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	var out struct {
		Token       string `json:"token"`
		ExpiresUnix int64  `json:"expires_unix"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return AuthToken{}, err
	}
	return AuthToken{Token: out.Token, Expires: time.Unix(out.ExpiresUnix, 0).UTC()}, nil
}
func (c *AuthClient) registerWithSigner(ctx context.Context, userID string, signer ssh.Signer) error {
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return c.RegisterAuthorizedKey(ctx, userID, pub)
}

func (c *AuthClient) doJSON(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(buf)
	} else {
		reader = bytes.NewReader(nil)
	}
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.hc.Do(req)
}

func decodeError(resp *http.Response) string {
	defer func() {
		_ = resp.Body.Close()
	}()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Error == "" {
		return resp.Status
	}
	return body.Error
}

func loadSignerFromPath(path string, passphrase []byte) (ssh.Signer, error) {
	path, err := expandPath(path)
	if err != nil {
		return nil, err
	}
	// #nosec G304 -- user controls key path intentionally to load SSH credentials.
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(passphrase) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(keyBytes, passphrase)
	}
	return ssh.ParsePrivateKey(keyBytes)
}

func expandPath(p string) (string, error) {
	if p == "" {
		return p, errors.New("path required")
	}
	if p[0] != '~' {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if p == "~" {
		return home, nil
	}
	p = strings.TrimPrefix(p, "~")
	p = strings.TrimPrefix(p, string(os.PathSeparator))
	return filepath.Join(home, p), nil
}

// DefaultSSHKeyPath returns ~/.ssh/id_ed25519 if HOME is known.
func DefaultSSHKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "~/.ssh/id_ed25519"
	}
	return filepath.Join(home, ".ssh", "id_ed25519")
}
