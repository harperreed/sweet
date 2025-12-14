package main

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

type pocketBaseClient struct {
	baseURL string
	client  *http.Client
}

func newPocketBaseClient(baseURL string) (*pocketBaseClient, error) {
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, errors.New("pocketbase url required")
	}
	return &pocketBaseClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *pocketBaseClient) Register(ctx context.Context, username, email, password, userID string) error {
	body := map[string]string{
		"username":        username,
		"email":           email,
		"password":        password,
		"passwordConfirm": password,
		"user_id":         userID,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/collections/users/records", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("pocketbase register failed: %s", resp.Status)
	}
	return nil
}

func (c *pocketBaseClient) Login(ctx context.Context, username, password string) error {
	body := map[string]string{
		"identity": username,
		"password": password,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/collections/users/auth-with-password", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pocketbase login failed: %s", resp.Status)
	}
	return nil
}
