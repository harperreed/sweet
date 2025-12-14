Yep — make it a **shared Go library** that your `todo`, `notes`, and `logger` binaries import.

Below is a solid “Atuin-ish” core you can drop into a repo as a module, then each CLI just defines its entity payloads and calls `core.Upsert/Append/Delete + core.Sync()`.

---

## Repo shape

```
syncvault/
  go.mod
  vault/
    config.go
    seed.go
    keys.go
    crypto.go
    change.go
    store_sqlite.go
    client_http.go
    sync.go
  cmd/
    todo/   (uses vault/)
    notes/
    logger/
```

---

## The library: `vault/` (copy/paste)

### `vault/config.go`

```go
package vault

import "time"

// KDFParams controls Argon2id hardness.
// Beefy defaults: 256MB, 2 iters, 1 thread.
type KDFParams struct {
	MemoryMB uint32
	Time     uint32
	Threads  uint8
	KeyLen   uint32
}

// DefaultKDFParams returns "beefy but reasonable" params for laptops/desktops.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		MemoryMB: 256,
		Time:     2,
		Threads:  1,
		KeyLen:   32,
	}
}

type SyncConfig struct {
	BaseURL   string        // e.g. https://vault.example.com
	DeviceID  string        // stable per machine
	AuthToken string        // short-lived token from SSH login flow
	Timeout   time.Duration // HTTP timeout
}
```

### `vault/seed.go` (seed phrase generation + parsing)

This uses a simple wordlist approach placeholder. If you want real BIP-39 compatibility, swap this file for a BIP-39 lib (I’ll note options below).

```go
package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

// SeedPhrase represents your human-portable secret.
// Implementation choice:
// - For now we use a 32-byte random seed encoded as 64 hex chars.
// - Swap to BIP-39 later without changing downstream key derivation.
type SeedPhrase struct {
	Raw []byte // 32 bytes
}

// NewSeedPhrase generates a new random seed.
func NewSeedPhrase() (SeedPhrase, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return SeedPhrase{}, "", err
	}
	phrase := hex.EncodeToString(b) // "seed phrase" string; replace w/ 24 words later
	return SeedPhrase{Raw: b}, phrase, nil
}

// ParseSeedPhrase parses a phrase string into raw seed bytes.
func ParseSeedPhrase(phrase string) (SeedPhrase, error) {
	phrase = strings.TrimSpace(phrase)
	b, err := hex.DecodeString(phrase)
	if err != nil {
		return SeedPhrase{}, err
	}
	if len(b) != 32 {
		return SeedPhrase{}, errors.New("seed must decode to 32 bytes")
	}
	return SeedPhrase{Raw: b}, nil
}
```

### `vault/keys.go` (seed → master key → subkeys)

```go
package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Keys are derived deterministically from the seed (+ optional passphrase).
type Keys struct {
	EncKey  [32]byte // payload encryption key (XChaCha20-Poly1305)
	UserKey [32]byte // stable per-user key material (for user_id)
}

// DeriveKeys derives deterministic keys from the seed phrase.
// passphrase can be "".
// salt is a constant domain separator, NOT secret.
func DeriveKeys(seed SeedPhrase, passphrase string, params KDFParams) (Keys, error) {
	// 1) Derive Master Key (MK) with Argon2id (slow).
	// We mix passphrase into the input; you can also do it as separate salt or HKDF stage.
	input := append([]byte{}, seed.Raw...)
	input = append(input, []byte(passphrase)...)

	salt := []byte("syncvault:v1:argon2id") // constant domain separator

	mk := argon2.IDKey(
		input,
		salt,
		params.Time,
		params.MemoryMB*1024, // Argon2 expects KiB
		params.Threads,
		params.KeyLen,
	)

	// 2) Expand MK into subkeys with HKDF-SHA256 (fast).
	var out Keys

	enc := hkdf.New(sha256.New, mk, nil, []byte("syncvault:v1:enc"))
	if _, err := io.ReadFull(enc, out.EncKey[:]); err != nil {
		return Keys{}, err
	}

	uid := hkdf.New(sha256.New, mk, nil, []byte("syncvault:v1:user"))
	if _, err := io.ReadFull(uid, out.UserKey[:]); err != nil {
		return Keys{}, err
	}

	// Best practice: wipe mk if you care (Go doesn’t guarantee, but we can at least overwrite).
	for i := range mk {
		mk[i] = 0
	}
	return out, nil
}

// UserID returns a stable, non-secret identifier derived from UserKey.
// You can use this for server partitioning without exposing plaintext.
func (k Keys) UserID() string {
	sum := sha256.Sum256(k.UserKey[:])
	return hex.EncodeToString(sum[:16]) // 128-bit hex; plenty for ID
}
```

### `vault/crypto.go` (encrypt/decrypt changes)

```go
package vault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Envelope is what you store/send. Server never sees plaintext.
type Envelope struct {
	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`
}

// Encrypt encrypts plaintext with XChaCha20-Poly1305.
// aad is authenticated (tamper-proof) but not encrypted.
func Encrypt(encKey [32]byte, plaintext, aad []byte) (Envelope, error) {
	aead, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		return Envelope{}, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}

	ct := aead.Seal(nil, nonce, plaintext, aad)

	return Envelope{
		NonceB64: base64.StdEncoding.EncodeToString(nonce),
		CTB64:    base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Decrypt decrypts an Envelope back into plaintext.
func Decrypt(encKey [32]byte, env Envelope, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(encKey[:])
	if err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(env.NonceB64)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid nonce size")
	}

	ct, err := base64.StdEncoding.DecodeString(env.CTB64)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ct, aad)
}
```

### `vault/change.go` (typed change events)

```go
package vault

import (
	"encoding/json"
	"time"

	"github.com/oklog/ulid/v2"
)

// Op describes a logical operation.
type Op string

const (
	OpUpsert Op = "upsert"
	OpDelete Op = "delete"
	OpAppend Op = "append" // good for logs
)

// Change is the logical event (plaintext before encryption).
type Change struct {
	ChangeID string          `json:"change_id"`
	Entity   string          `json:"entity"`    // "todo" | "note" | "log" | etc.
	EntityID string          `json:"entity_id"` // stable per record
	Op       Op              `json:"op"`
	TS       time.Time       `json:"ts"`
	Payload  json.RawMessage `json:"payload,omitempty"` // entity-specific
	Deleted  bool            `json:"deleted,omitempty"` // optional
}

// NewChange creates a new change with ULID id.
func NewChange(entity, entityID string, op Op, payload any) (Change, error) {
	id := ulid.Make().String()

	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return Change{}, err
		}
		raw = b
	}

	return Change{
		ChangeID: id,
		Entity:   entity,
		EntityID: entityID,
		Op:       op,
		TS:       time.Now().UTC(),
		Payload:  raw,
	}, nil
}

// AAD binds ciphertext to these fields so they can't be swapped.
func (c Change) AAD(userID, deviceID string) []byte {
	// Keep it deterministic and minimal.
	// If you add fields, you must keep backwards compatibility (version prefix helps).
	return []byte("v1|" + userID + "|" + deviceID + "|" + c.ChangeID + "|" + c.Entity)
}
```

### `vault/store_sqlite.go` (local offline store + outbox)

This is a minimal working store. Your app layer can maintain entity tables; the vault store just tracks changes + sync state.

```go
package vault

import (
	"context"
	"database/sql"
	_ "modernc.org/sqlite"
)

// Store manages local persistence of encrypted sync changes + sync state.
type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS outbox (
  change_id TEXT PRIMARY KEY,
  entity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  op TEXT NOT NULL,
  ts INTEGER NOT NULL,
  aad TEXT NOT NULL,
  nonce_b64 TEXT NOT NULL,
  ct_b64 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applied (
  change_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sync_state (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`)
	return err
}

// EnqueueEncryptedChange stores an encrypted change ready to push.
func (s *Store) EnqueueEncryptedChange(ctx context.Context, c Change, userID, deviceID string, env Envelope) error {
	aad := string(c.AAD(userID, deviceID))
	_, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO outbox(change_id, entity, entity_id, op, ts, aad, nonce_b64, ct_b64)
VALUES(?,?,?,?,?,?,?,?)`,
		c.ChangeID, c.Entity, c.EntityID, string(c.Op), c.TS.Unix(), aad, env.NonceB64, env.CTB64,
	)
	return err
}

// DequeueBatch returns N outbox envelopes for pushing.
func (s *Store) DequeueBatch(ctx context.Context, limit int) ([]string, []Envelope, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT change_id, nonce_b64, ct_b64 FROM outbox ORDER BY ts ASC LIMIT ?`, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var ids []string
	var envs []Envelope
	for rows.Next() {
		var id, n, ct string
		if err := rows.Scan(&id, &n, &ct); err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		envs = append(envs, Envelope{NonceB64: n, CTB64: ct})
	}
	return ids, envs, rows.Err()
}

// AckOutbox removes successfully pushed changes.
func (s *Store) AckOutbox(ctx context.Context, changeIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `DELETE FROM outbox WHERE change_id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, id := range changeIDs {
		if _, err := stmt.ExecContext(ctx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetState(ctx context.Context, key, def string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM sync_state WHERE k = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return def, nil
	}
	return v, err
}

func (s *Store) SetState(ctx context.Context, key, val string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sync_state(k,v) VALUES(?,?)
ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, val)
	return err
}
```

### `vault/client_http.go` (push/pull)

```go
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	cfg SyncConfig
	hc  *http.Client
}

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

type PushReq struct {
	UserID   string     `json:"user_id"`
	DeviceID string     `json:"device_id"`
	Changes  []PushItem `json:"changes"`
}
type PushItem struct {
	ChangeID string   `json:"change_id"`
	Env      Envelope `json:"env"`
}

type PushResp struct {
	Ack []string `json:"ack_change_ids"`
}

func (c *Client) Push(ctx context.Context, userID string, items []PushItem) (PushResp, error) {
	reqBody, _ := json.Marshal(PushReq{
		UserID:   userID,
		DeviceID: c.cfg.DeviceID,
		Changes:  items,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.BaseURL+"/v1/sync/push", bytes.NewReader(reqBody))
	if err != nil {
		return PushResp{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return PushResp{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return PushResp{}, fmt.Errorf("push failed: %s", resp.Status)
	}

	var out PushResp
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

type PullResp struct {
	// seq is server-assigned monotonic per-user.
	Items []PullItem `json:"items"`
}
type PullItem struct {
	Seq      int64    `json:"seq"`
	ChangeID string   `json:"change_id"`
	DeviceID string   `json:"device_id"`
	Entity   string   `json:"entity"`
	Env      Envelope `json:"env"`
	// server can include whatever non-sensitive metadata you want for routing/debug
}

func (c *Client) Pull(ctx context.Context, userID string, sinceSeq int64) (PullResp, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
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
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return PullResp{}, fmt.Errorf("pull failed: %s", resp.Status)
	}

	var out PullResp
	return out, json.NewDecoder(resp.Body).Decode(&out)
}
```

### `vault/sync.go` (wire it together)

You provide an `ApplyFn` that knows how to apply a decrypted `Change` into your app’s SQLite tables.

```go
package vault

import (
	"context"
	"encoding/json"
	"strconv"
)

// ApplyFn applies a decrypted change into app state.
// Must be idempotent (safe to re-run).
type ApplyFn func(ctx context.Context, c Change) error

// Sync pushes local outbox then pulls remote changes and applies them.
func Sync(ctx context.Context, store *Store, client *Client, keys Keys, apply ApplyFn) error {
	userID := keys.UserID()

	// --- PUSH ---
	ids, envs, err := store.DequeueBatch(ctx, 200)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		items := make([]PushItem, 0, len(ids))
		for i := range ids {
			items = append(items, PushItem{ChangeID: ids[i], Env: envs[i]})
		}
		resp, err := client.Push(ctx, userID, items)
		if err != nil {
			return err
		}
		if err := store.AckOutbox(ctx, resp.Ack); err != nil {
			return err
		}
	}

	// --- PULL ---
	sinceStr, err := store.GetState(ctx, "last_pulled_seq", "0")
	if err != nil {
		return err
	}
	since, _ := strconv.ParseInt(sinceStr, 10, 64)

	pull, err := client.Pull(ctx, userID, since)
	if err != nil {
		return err
	}

	maxSeq := since
	for _, it := range pull.Items {
		// NOTE: You need AAD consistent with your Change.AAD() implementation.
		// Since ChangeID and Entity are in AAD, server must return Entity too.
		aad := []byte("v1|" + userID + "|" + it.DeviceID + "|" + it.ChangeID + "|" + it.Entity)

		plain, err := Decrypt(keys.EncKey, it.Env, aad)
		if err != nil {
			return err
		}
		var c Change
		if err := json.Unmarshal(plain, &c); err != nil {
			return err
		}

		// Apply into app DB/tables.
		if err := apply(ctx, c); err != nil {
			return err
		}

		if it.Seq > maxSeq {
			maxSeq = it.Seq
		}
	}

	if maxSeq != since {
		if err := store.SetState(ctx, "last_pulled_seq", strconv.FormatInt(maxSeq, 10)); err != nil {
			return err
		}
	}
	return nil
}
```

---

## How your CLIs use it

Each tool:

1. opens its app DB (can be same SQLite file)
2. derives keys from seed phrase
3. when it mutates state, it:

   * writes to its local table(s)
   * creates a `Change`
   * encrypts it
   * enqueues it in `outbox`
4. runs `vault.Sync(...)` periodically or on demand

Example “upsert todo” snippet:

```go
// 1) Build logical change
chg, _ := vault.NewChange("todo", todoID, vault.OpUpsert, map[string]any{
	"text": text,
	"done": done,
	"updated_at": time.Now().UTC().Unix(),
})

// 2) Encrypt
userID := keys.UserID()
aad := chg.AAD(userID, deviceID)
plain, _ := json.Marshal(chg)
env, _ := vault.Encrypt(keys.EncKey, plain, aad)

// 3) Enqueue for sync
_ = store.EnqueueEncryptedChange(ctx, chg, userID, deviceID, env)
```

Then call `vault.Sync(...)` with an `ApplyFn` that upserts into your `todos` table.

---

## Two practical notes

### 1) Seed phrase format

Right now I used a **hex string** as the “seed phrase” to keep this fully self-contained.

If you want real **24-word BIP-39**, swap `seed.go` to use a BIP-39 lib. The rest of the library stays identical (because everything downstream takes `SeedPhrase.Raw []byte`).

### 2) Auth flow

I didn’t implement the SSH challenge/response here (it’s server-facing + some client glue). The above assumes you already have `AuthToken`. You can add `vault/auth_ssh.go` later without touching crypto/sync.

---

## Next: I can give you the server in ~150–250 lines

If you tell me where you want to host it (Fly.io? VPS? Cloud Run?), I’ll sketch:

* the exact HTTP handlers (`/v1/sync/push`, `/v1/sync/pull`)
* Postgres schema
* SSH challenge verification
* rate limiting + basic abuse protection

And if you want, I’ll also show how to make all three CLIs share a single `ApplyFn` registry (`entity -> handler`) so adding new utilities is trivial.
