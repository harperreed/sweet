# Vault Integration Guide

A step-by-step guide for integrating your Go application with the vault E2E encrypted sync library.

## Overview

The vault library provides:
- E2E encrypted sync using XChaCha20-Poly1305
- BIP39 mnemonic seed phrases for key derivation
- Local SQLite outbox for offline-first operation
- Push/pull sync with monotonic ordering
- PocketBase authentication

## Quick Start

### 1. Add the Dependency

```bash
# If using the github module directly
go get github.com/harperreed/sweet

# Or with a replace directive for local development
```

In `go.mod`:
```go
require (
    suitesync v0.1.3
)

replace suitesync => github.com/harperreed/sweet v0.1.3
```

### 2. Create Your Sync Config

Create a config struct that stores sync settings. The key insight is to store the **hex-encoded seed** (not the mnemonic) in your config file.

```go
// internal/sync/config.go
package sync

import (
    "encoding/json"
    "os"
    "path/filepath"

    "github.com/oklog/ulid/v2"
)

type Config struct {
    Server       string `json:"server"`
    UserID       string `json:"user_id"`
    Token        string `json:"token"`
    RefreshToken string `json:"refresh_token,omitempty"`
    TokenExpires string `json:"token_expires,omitempty"`
    DerivedKey   string `json:"derived_key"` // hex-encoded seed, NOT the mnemonic
    DeviceID     string `json:"device_id"`
    VaultDB      string `json:"vault_db"`
    AutoSync     bool   `json:"auto_sync"`   // Sync automatically after each write
}

func ConfigDir() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".config", "yourapp")
}

func ConfigPath() string {
    return filepath.Join(ConfigDir(), "sync.json")
}

func LoadConfig() (*Config, error) {
    data, err := os.ReadFile(ConfigPath())
    if err != nil {
        return &Config{VaultDB: filepath.Join(ConfigDir(), "vault.db")}, nil
    }
    var cfg Config
    if err := json.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    return &cfg, nil
}

func SaveConfig(cfg *Config) error {
    if err := os.MkdirAll(ConfigDir(), 0750); err != nil {
        return err
    }
    data, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(ConfigPath(), data, 0600)
}

func (c *Config) IsConfigured() bool {
    return c.DerivedKey != "" && c.Token != "" && c.Server != "" && c.UserID != ""
}

func GenerateDeviceID() string {
    return ulid.Make().String()
}
```

### 3. Create the Sync Wrapper

The syncer wraps vault operations and provides methods for your specific entities.

```go
// internal/sync/sync.go
package sync

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "time"

    "github.com/google/uuid"
    "suitesync/vault"
)

type Syncer struct {
    config *Config
    store  *vault.Store
    keys   vault.Keys
    client *vault.Client
    appDB  *sql.DB
}

func NewSyncer(cfg *Config, appDB *sql.DB) (*Syncer, error) {
    if cfg.DerivedKey == "" {
        return nil, fmt.Errorf("derived key not configured")
    }

    // DerivedKey is stored as hex-encoded seed
    seed, err := vault.ParseSeedPhrase(cfg.DerivedKey)
    if err != nil {
        return nil, fmt.Errorf("invalid derived key: %w", err)
    }

    keys, err := vault.DeriveKeys(seed, "", vault.DefaultKDFParams())
    if err != nil {
        return nil, fmt.Errorf("derive keys: %w", err)
    }

    store, err := vault.OpenStore(cfg.VaultDB)
    if err != nil {
        return nil, fmt.Errorf("open vault store: %w", err)
    }

    client := vault.NewClient(vault.SyncConfig{
        BaseURL:   cfg.Server,
        DeviceID:  cfg.DeviceID,
        AuthToken: cfg.Token,
    })

    return &Syncer{
        config: cfg,
        store:  store,
        keys:   keys,
        client: client,
        appDB:  appDB,
    }, nil
}

func (s *Syncer) Close() error {
    return s.store.Close()
}

// getVersion returns the current version of an entity (0 if not found)
func (s *Syncer) getVersion(ctx context.Context, entity, entityID string) (int, error) {
    var version int
    err := s.appDB.QueryRowContext(ctx,
        `SELECT version FROM records WHERE entity = ? AND entity_id = ?`,
        entity, entityID,
    ).Scan(&version)
    if err == sql.ErrNoRows {
        return 0, nil
    }
    return version, err
}
```

### 4. Define Your Entities

For each entity type you want to sync, define a payload struct and queue methods.

```go
// Example: syncing "item" and "position" entities

type ItemPayload struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}

type PositionPayload struct {
    ID         string   `json:"id"`
    ItemName   string   `json:"item_name"`
    Latitude   float64  `json:"latitude"`
    Longitude  float64  `json:"longitude"`
    Label      *string  `json:"label,omitempty"`
    RecordedAt string   `json:"recorded_at"`
}

func (s *Syncer) QueueItemChange(ctx context.Context, id uuid.UUID, name string, op vault.Op) error {
    payload := ItemPayload{
        ID:   id.String(),
        Name: name,
    }

    // Get current version for conflict detection (0 if new)
    baseVersion, _ := s.getVersion(ctx, "item", id.String())

    // NewChangeWithVersion tracks version for conflict resolution
    change, err := vault.NewChangeWithVersion("item", id.String(), op, payload, baseVersion)
    if err != nil {
        return fmt.Errorf("create change: %w", err)
    }

    // IMPORTANT: Use the same userID for AAD and Sync() calls
    userID := s.config.UserID
    aad := change.AAD(userID, s.config.DeviceID)
    plaintext, err := json.Marshal(change)
    if err != nil {
        return fmt.Errorf("marshal change: %w", err)
    }

    env, err := vault.Encrypt(s.keys.EncKey, plaintext, aad)
    if err != nil {
        return fmt.Errorf("encrypt: %w", err)
    }

    if err := s.store.EnqueueEncryptedChange(ctx, change, userID, s.config.DeviceID, env); err != nil {
        return err
    }

    // Auto-sync if enabled
    if s.config.AutoSync {
        return s.Sync(ctx)
    }
    return nil
}
```

### 5. Implement the Apply Handler

When syncing, incoming changes need to be applied to your local database.

```go
func (s *Syncer) Sync(ctx context.Context) error {
    return vault.Sync(ctx, s.store, s.client, s.keys, s.config.UserID, s.applyChange)
}

func (s *Syncer) applyChange(ctx context.Context, c vault.Change) error {
    switch c.Entity {
    case "item":
        return s.applyItemChange(ctx, c)
    case "position":
        return s.applyPositionChange(ctx, c)
    default:
        // Unknown entity - skip (forward compatibility)
        return nil
    }
}

func (s *Syncer) applyItemChange(ctx context.Context, c vault.Change) error {
    var payload ItemPayload
    if err := json.Unmarshal(c.Payload, &payload); err != nil {
        return fmt.Errorf("unmarshal item payload: %w", err)
    }

    switch c.Op {
    case vault.OpUpsert:
        // Upsert into your items table
        _, err := s.appDB.ExecContext(ctx, `
            INSERT INTO items (id, name, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET name = excluded.name`,
            payload.ID, payload.Name, time.Now(),
        )
        return err

    case vault.OpDelete:
        _, err := s.appDB.ExecContext(ctx, `DELETE FROM items WHERE id = ?`, payload.ID)
        return err
    }

    return nil
}
```

### 6. Wire Into Your Commands

Call your sync methods after local mutations. With `AutoSync: true`, changes sync immediately.

```go
import "log"

// In your "add" command
func addItem(ctx context.Context, name string) error {
    // 1. Create locally
    item := models.NewItem(name)
    if err := db.CreateItem(dbConn, item); err != nil {
        return err
    }

    // 2. Queue for sync
    cfg, err := sync.LoadConfig()
    if err != nil {
        log.Printf("warning: could not load sync config: %v", err)
        return nil // Local create succeeded, sync is optional
    }

    if !cfg.IsConfigured() {
        return nil // Sync not configured, that's fine
    }

    syncer, err := sync.NewSyncer(cfg, dbConn)
    if err != nil {
        log.Printf("warning: could not initialize syncer: %v", err)
        return nil
    }
    defer func() { _ = syncer.Close() }()

    if err := syncer.QueueItemChange(ctx, item.ID, item.Name, vault.OpUpsert); err != nil {
        log.Printf("warning: failed to queue sync: %v", err)
        // Don't fail the command - local create succeeded
    }

    // If AutoSync is enabled, this already synced in QueueItemChange
    // Otherwise, changes will sync on next explicit `sync now` command

    return nil
}
```

### 7. Implement Auth Commands

Use PocketBase authentication for login/register.

```go
import (
    "context"
    "encoding/hex"
    "fmt"
    "path/filepath"
    "time"

    "suitesync/vault"
)

func login(server, email, password, mnemonic string) error {
    // Validate mnemonic
    if _, err := vault.ParseMnemonic(mnemonic); err != nil {
        return fmt.Errorf("invalid recovery phrase: %w", err)
    }

    // Login to server
    client := vault.NewPBAuthClient(server)
    result, err := client.Login(context.Background(), email, password)
    if err != nil {
        return fmt.Errorf("login failed: %w", err)
    }

    // Convert mnemonic to hex seed for storage (never store the mnemonic!)
    seed, err := vault.ParseSeedPhrase(mnemonic)
    if err != nil {
        return err
    }
    derivedKeyHex := hex.EncodeToString(seed.Raw)

    // Save config
    cfg := &Config{
        Server:       server,
        UserID:       result.UserID,
        Token:        result.Token.Token,
        RefreshToken: result.RefreshToken,
        TokenExpires: result.Token.Expires.Format(time.RFC3339),
        DerivedKey:   derivedKeyHex,
        DeviceID:     GenerateDeviceID(),
        VaultDB:      filepath.Join(ConfigDir(), "vault.db"),
        AutoSync:     true, // Enable auto-sync by default
    }

    return SaveConfig(cfg)
}
```

## Key Concepts

### Dual Storage Pattern

Keep your app's data in its own schema. Mirror changes to the vault outbox:

```
┌─────────────────┐     ┌─────────────────┐
│   Your App DB   │     │   Vault DB      │
│                 │     │                 │
│  items table    │────▶│  outbox table   │
│  positions tbl  │     │  applied table  │
│  ...            │     │  sync_state     │
└─────────────────┘     └─────────────────┘
```

This lets users optionally enable sync without changing your core data model.

### Entity Design

Each sync entity needs:
- **Entity name**: String identifier (e.g., "item", "position")
- **Entity ID**: Stable UUID for the record
- **Payload**: JSON-serializable struct with all data needed to reconstruct

Design payloads to be self-contained. Include foreign key references by name/value, not just ID:

```go
// Good: includes item_name so position can be reconstructed
type PositionPayload struct {
    ID       string `json:"id"`
    ItemName string `json:"item_name"` // Can lookup/create item
    Lat      float64 `json:"lat"`
    Lng      float64 `json:"lng"`
}

// Bad: only has item_id, can't reconstruct if item doesn't exist
type PositionPayload struct {
    ID     string `json:"id"`
    ItemID string `json:"item_id"` // What if item not synced yet?
    Lat    float64 `json:"lat"`
    Lng    float64 `json:"lng"`
}
```

### Operations

Three operations are supported:

| Op | When to Use |
|----|-------------|
| `vault.OpUpsert` | Create or update a record |
| `vault.OpDelete` | Remove a record |
| `vault.OpAppend` | Append-only logs (immutable entries) |

### Auto-Sync

When `AutoSync: true` is set in config, changes sync immediately after being queued:

```go
// Config option
cfg.AutoSync = true

// Or via environment variable
export YOURAPP_AUTO_SYNC=1
```

With auto-sync disabled, changes queue locally and sync on explicit `sync now` commands. This is useful for:
- Batch operations (queue many, sync once)
- Offline-first workflows
- Reducing network traffic

### Security Notes

1. **Never store the mnemonic** - Only store `hex.EncodeToString(seed.Raw)`
2. **Config file permissions** - Use `0600` for config files
3. **Token refresh** - Implement token refresh for long-running sessions
4. **AAD binding** - The AAD (Additional Authenticated Data) prevents tampering

## Complete Example

See the [position](https://github.com/harperreed/position) CLI for a complete working integration:

- `internal/sync/config.go` - Config management
- `internal/sync/sync.go` - Syncer with entity handlers
- `cmd/position/sync.go` - CLI commands (init, login, status, now, logout)
- `cmd/position/add.go` - Wiring sync into mutations

## Common Pitfalls

### UserID Mismatch (AAD Error)

**Symptom:** `chacha20poly1305: message authentication failed` during sync pull

**Cause:** Using different `userID` values for encryption vs sync. The AAD (Additional Authenticated Data) must match exactly between encryption and decryption.

**Wrong:**
```go
// Encryption - using vault-derived ID
aad := change.AAD(s.keys.UserID(), s.config.DeviceID)

// Sync - using PocketBase ID (DIFFERENT!)
vault.Sync(ctx, store, client, keys, s.config.UserID, apply)
```

**Right:**
```go
// Pick ONE identifier and use it consistently
userID := s.config.UserID  // PocketBase record ID

// Encryption
aad := change.AAD(userID, s.config.DeviceID)

// Sync - same userID
vault.Sync(ctx, store, client, keys, userID, apply)
```

The vault library is flexible - it doesn't care which identifier you use. Just be consistent:
- `change.AAD(userID, deviceID)` during encryption
- `vault.Sync(..., userID, ...)` during sync

Both `keys.UserID()` (vault-derived) and PocketBase record IDs work fine. Pick one.

## Troubleshooting

### "derived key not configured"
Run `yourapp sync login` to authenticate and store the derived key.

### "go mod verify" fails with replace directive
This is expected. Use `SKIP=go-mod-verify` in pre-commit hooks or remove the verify hook.

### Changes not appearing on other devices
1. Check `yourapp sync status` for pending changes
2. Run `yourapp sync now` on both devices
3. Verify both devices use the same recovery phrase

### "invalid recovery phrase"
The mnemonic must be either:
- 24 BIP39 words separated by spaces
- 64-character hex string
