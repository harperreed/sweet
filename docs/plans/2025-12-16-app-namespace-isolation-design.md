# App Namespace Isolation Design

Prevent multiple apps sharing a sync account from interfering with each other's data.

## Problem

Multiple apps using the same sync account can clobber each other's data:
1. Position creates an `item` entity
2. Sweet also uses `item` entities
3. Sweet deletes an item
4. Position pulls the DELETE and loses its data

## Solution

Each app gets a unique namespace (UUID). Entities are prefixed with the app's UUID, and the prefix is included in AAD for cryptographic isolation.

## Core Concept

**Developer hardcodes UUID:**
```go
const appID = "550e8400-e29b-41d4-a716-446655440000"

client := vault.NewClient(vault.SyncConfig{
    AppID:     appID,  // Required, panics if empty
    BaseURL:   cfg.Server,
    AuthToken: cfg.Token,
    DeviceID:  cfg.DeviceID,
})
```

**Entity transformation:**
- Developer writes: `vault.NewChange("item", id, op, payload)`
- Library stores: entity = `550e8400-e29b-41d4-a716-446655440000.item`

**AAD transformation:**
- Old: `v1|userID|deviceID|changeID|item`
- New: `v1|userID|deviceID|changeID|550e8400-e29b-41d4-a716-446655440000.item`

**Cryptographic isolation:** If Position tries to decrypt Sweet's data, AAD mismatch causes decryption failure. Even bugs can't leak data across apps.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| AppID format | UUID | Collision-proof, no coordination needed |
| AppID source | Hardcoded in app | Users can't accidentally change it |
| Namespace location | Entity name + AAD | Cryptographic isolation as safety net |
| Server behavior | Agnostic | Crypto does the heavy lifting |
| Backward compat | None (wipe old data) | Simpler, not much existing data |
| Empty AppID | Panic | Forces developers to set it |

## Library Changes

### SyncConfig

```go
type SyncConfig struct {
    AppID        string        // NEW: Required UUID, panics if empty
    BaseURL      string
    DeviceID     string
    AuthToken    string
    RefreshToken string
    TokenExpires time.Time
    Timeout      time.Duration
    OnTokenRefresh func(token, refresh string, expires time.Time)
}
```

### NewClient Validation

```go
func NewClient(cfg SyncConfig) *Client {
    if cfg.AppID == "" {
        panic("vault: AppID is required - generate a UUID and hardcode it")
    }
    if !isValidUUID(cfg.AppID) {
        panic("vault: AppID must be a valid UUID")
    }
    // ... rest of constructor
}

func isValidUUID(s string) bool {
    _, err := uuid.Parse(s)
    return err == nil
}
```

### Internal Helpers

```go
func (c *Client) prefixedEntity(entity string) string {
    return c.cfg.AppID + "." + entity
}

func (c *Client) stripPrefix(entity string) string {
    prefix := c.cfg.AppID + "."
    return strings.TrimPrefix(entity, prefix)
}
```

## Push Flow

Entity is prefixed before encryption:

```go
func (s *Syncer) QueueChange(entity, entityID string, op Op, payload any) error {
    // Prefix entity with AppID
    prefixedEntity := s.client.prefixedEntity(entity)

    change, _ := vault.NewChange(prefixedEntity, entityID, op, payload)
    aad := change.AAD(userID, deviceID)  // AAD includes prefixed entity
    env, _ := vault.Encrypt(keys.EncKey, plaintext, aad)
    return s.store.EnqueueEncryptedChange(ctx, change, userID, deviceID, env)
}
```

## Pull Flow

Filter by namespace, strip prefix before applying:

```go
for _, it := range pull.Items {
    // Only process items from our app namespace
    if !strings.HasPrefix(it.Entity, appID+".") {
        continue  // Skip other apps' data
    }

    aad := []byte("v1|" + userID + "|" + it.DeviceID + "|" + it.ChangeID + "|" + it.Entity)
    plain, err := Decrypt(keys.EncKey, it.Env, aad)
    if err != nil {
        return &DecryptError{
            ChangeID: it.ChangeID,
            Entity:   it.Entity,
            UserID:   userID,
            DeviceID: it.DeviceID,
            Cause:    err,
        }
    }

    var c Change
    json.Unmarshal(plain, &c)
    c.Entity = stripPrefix(c.Entity)  // App sees "item" not "uuid.item"

    apply(ctx, c)
}
```

## What Changes

| Component | Change |
|-----------|--------|
| `SyncConfig` | Add `AppID` field (required UUID) |
| `NewClient` | Panic if AppID empty or invalid UUID |
| Push flow | Prefix entity with AppID before encrypt |
| Pull flow | Filter by AppID prefix, strip before apply callback |
| AAD | Automatically includes prefixed entity |

## What Doesn't Change

- Server (agnostic to namespacing)
- Store/outbox (stores whatever entity string it gets)
- Application code (sees clean entity names like `item`)

## Migration for Existing Apps

1. Generate a UUID for your app: `uuidgen`
2. Wipe existing server data: `curl -X POST -H "Authorization: Bearer $TOKEN" $SERVER/v1/sync/wipe`
3. Delete local vault.db: `rm ~/.config/yourapp/vault.db`
4. Update app code with AppID in SyncConfig
5. Resync fresh

## Implementation Tasks

1. Add `AppID` field to `SyncConfig`
2. Add UUID validation to `NewClient`
3. Add `prefixedEntity` and `stripPrefix` helpers
4. Update push flow to prefix entities
5. Update pull flow to filter and strip prefix
6. Update all apps (sweet, position, etc.) with UUIDs
7. Add tests for namespace isolation

## Security Properties

- **Collision-proof:** UUIDs can't accidentally match
- **Cryptographic isolation:** Wrong-app data fails decryption
- **Defense in depth:** Filter + crypto both prevent cross-app access
- **Immutable:** AppID hardcoded, users can't change it
