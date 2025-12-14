package pocketbase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AccountInfo is the subset of PocketBase user data the sync server needs.
type AccountInfo struct {
	ID           string
	Email        string
	Active       bool
	Plan         string
	QuotaChanges int
	UserID       string
}

// Client describes the control-plane contract used by the sync server.
type Client interface {
	GetAccountByUserID(ctx context.Context, userID string) (AccountInfo, error)
	IncrementUsage(ctx context.Context, userID string, changes int) error
}

// NoopClient is used when PocketBase isn't configured.
type NoopClient struct{}

func (NoopClient) GetAccountByUserID(ctx context.Context, userID string) (AccountInfo, error) {
	return AccountInfo{UserID: userID, Active: true}, nil
}

func (NoopClient) IncrementUsage(ctx context.Context, userID string, changes int) error {
	return nil
}

// HTTPClient talks to PocketBase via HTTP API using an admin token.
type HTTPClient struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func (c *HTTPClient) httpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (c *HTTPClient) adminRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	if c.BaseURL == "" || c.Token == "" {
		return nil, errors.New("pocketbase url/token required")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "AdminToken "+c.Token)
	return c.httpClient().Do(req)
}

func (c *HTTPClient) GetAccountByUserID(ctx context.Context, userID string) (AccountInfo, error) {
	values := url.Values{}
	values.Set("filter", fmt.Sprintf("user_id=\"%s\"", userID))
	values.Set("perPage", "1")
	resp, err := c.adminRequest(ctx, http.MethodGet, "/api/collections/users/records?"+values.Encode(), nil)
	if err != nil {
		return AccountInfo{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return AccountInfo{}, errors.New("account not found")
		}
		return AccountInfo{}, fmt.Errorf("pocketbase: %s", resp.Status)
	}
	var doc struct {
		Items []struct {
			ID     string `json:"id"`
			Email  string `json:"email"`
			Active bool   `json:"active"`
			Plan   string `json:"plan"`
			Quota  int    `json:"quota_changes"`
			UserID string `json:"user_id"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return AccountInfo{}, err
	}
	if len(doc.Items) == 0 {
		return AccountInfo{}, errors.New("account not found")
	}
	it := doc.Items[0]
	return AccountInfo{
		ID:           it.ID,
		Email:        it.Email,
		Active:       it.Active,
		Plan:         it.Plan,
		QuotaChanges: it.Quota,
		UserID:       it.UserID,
	}, nil
}

func (c *HTTPClient) IncrementUsage(ctx context.Context, userID string, changes int) error {
	body := map[string]any{
		"user_id": userID,
		"delta":   changes,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.adminRequest(ctx, http.MethodPost, "/api/hooks/usage", payload)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pocketbase usage: %s", resp.Status)
	}
	return nil
}
