package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client performs push/pull RPCs against sync server.
type Client struct {
	cfg SyncConfig
	hc  *http.Client
}

// NewClient builds a client with optional timeout override.
func NewClient(cfg SyncConfig) *Client {
	to := cfg.Timeout
	if to == 0 {
		to = 15 * time.Second
	}
	return &Client{
		cfg: cfg,
		hc:  &http.Client{Timeout: to},
	}
}

// PushReq is sent by clients to upload encrypted changes.
type PushReq struct {
	UserID   string     `json:"user_id"`
	DeviceID string     `json:"device_id"`
	Changes  []PushItem `json:"changes"`
}

// PushItem carries entity metadata plus envelope for server fanout.
type PushItem struct {
	ChangeID string   `json:"change_id"`
	Entity   string   `json:"entity"`
	TS       int64    `json:"ts"`
	Env      Envelope `json:"env"`
	DeviceID string   `json:"device_id,omitempty"` // Optional per-item device_id (overrides request-level)
}

// PushResp acknowledges applied change IDs.
type PushResp struct {
	Ack []string `json:"ack_change_ids"`
}

// Push uploads queued envelopes.
func (c *Client) Push(ctx context.Context, userID string, items []PushItem) (PushResp, error) {
	payload := PushReq{
		UserID:   userID,
		DeviceID: c.cfg.DeviceID,
		Changes:  items,
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return PushResp{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/v1/sync/push", bytes.NewReader(reqBody))
	if err != nil {
		return PushResp{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return PushResp{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return PushResp{}, fmt.Errorf("push failed: %s", resp.Status)
	}

	var out PushResp
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// PullResp is returned by /v1/sync/pull.
type PullResp struct {
	Items []PullItem `json:"items"`
}

// PullItem is an encrypted change provided by the server.
type PullItem struct {
	Seq      int64    `json:"seq"`
	ChangeID string   `json:"change_id"`
	DeviceID string   `json:"device_id"`
	Entity   string   `json:"entity"`
	Env      Envelope `json:"env"`
	TS       int64    `json:"ts"`
}

// Pull fetches encrypted changes since sequence number.
func (c *Client) Pull(ctx context.Context, userID string, sinceSeq int64) (PullResp, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/v1/sync/pull?user_id=%s&since=%d", c.cfg.BaseURL, userID, sinceSeq),
		nil,
	)
	if err != nil {
		return PullResp{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)

	resp, err := c.hc.Do(req)
	if err != nil {
		return PullResp{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return PullResp{}, fmt.Errorf("pull failed: %s", resp.Status)
	}

	var out PullResp
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// PullRespWithSnapshot extends PullResp with optional snapshot.
type PullRespWithSnapshot struct {
	Items    []PullItem
	Snapshot *SnapshotInfo
}

// SnapshotInfo contains metadata and encrypted payload for a snapshot.
type SnapshotInfo struct {
	SnapshotID string   `json:"snapshot_id"`
	MinSeq     int64    `json:"min_seq"`
	CreatedAt  int64    `json:"created_at"`
	Env        Envelope `json:"env"`
}

// PullWithSnapshot fetches changes with optional snapshot for bootstrap.
func (c *Client) PullWithSnapshot(ctx context.Context, userID string, since int64, entity string) (PullRespWithSnapshot, error) {
	url := fmt.Sprintf("%s/v1/sync/pull?user_id=%s&since=%d", c.cfg.BaseURL, userID, since)
	if entity != "" {
		url += "&entity=" + entity
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PullRespWithSnapshot{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)

	resp, err := c.hc.Do(req)
	if err != nil {
		return PullRespWithSnapshot{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return PullRespWithSnapshot{}, fmt.Errorf("pull failed: %s", resp.Status)
	}

	var serverResp struct {
		Items    []PullItem    `json:"items"`
		Snapshot *SnapshotInfo `json:"snapshot,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&serverResp); err != nil {
		return PullRespWithSnapshot{}, err
	}

	return PullRespWithSnapshot{
		Items:    serverResp.Items,
		Snapshot: serverResp.Snapshot,
	}, nil
}

// Compact triggers server-side compaction of old changes for the given entity.
func (c *Client) Compact(ctx context.Context, userID, entity string) error {
	url := fmt.Sprintf("%s/v1/sync/compact?entity=%s", c.cfg.BaseURL, entity)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("compact failed: %s", resp.Status)
	}

	return nil
}
