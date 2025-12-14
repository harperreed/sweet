# Suite Sync v2: Multi-Device Enhancements

## Overview

This design addresses six gaps identified in the current suite-sync implementation to better support the single-user, multi-device use case (personal sync like 1Password/iCloud).

## 1. Multi-Device Authentication

### Problem
The current `users` table stores one SSH public key per `user_id`. Registering a new device overwrites the previous device's key, meaning only the last registered device can authenticate.

### Solution
Replace single-key model with a `devices` table supporting multiple devices per user.

### Schema Change

```sql
-- Drop the ssh_pubkey columns from users (or keep users minimal)
-- users table becomes: (user_id TEXT PRIMARY KEY, created_at INTEGER)

CREATE TABLE devices (
  device_id TEXT PRIMARY KEY,          -- client-generated UUID
  user_id TEXT NOT NULL,
  ssh_pubkey TEXT NOT NULL,
  ssh_pubkey_fp TEXT NOT NULL,         -- SHA256 fingerprint for lookup
  name TEXT,                           -- human-friendly name ("MacBook Pro")
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  UNIQUE(ssh_pubkey_fp)
);
CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_devices_fp ON devices(ssh_pubkey_fp);
```

### API Changes

- `POST /v1/auth/register`: Now creates a device record. Request adds optional `device_name` field.
- `GET /v1/devices?user_id=X`: List all devices for a user (requires auth).
- `DELETE /v1/devices/:device_id`: Revoke a device (requires auth, cannot revoke self).

### Auth Flow Change
Challenge verification looks up device by fingerprint rather than user_id, then checks the device's user_id matches.

---

## 2. Conflict Detection

### Problem
When two devices edit the same entity offline, last-write-wins by server `seq` order silently loses data.

### Solution
Add version tracking to detect conflicts. Surface conflicts to user rather than silent overwrite.

### Schema Change (Client-side `records` table)

```sql
ALTER TABLE records ADD COLUMN version INTEGER DEFAULT 0;
```

### Change Model Update

```go
type Change struct {
    ChangeID    string          `json:"change_id"`
    Entity      string          `json:"entity"`
    EntityID    string          `json:"entity_id"`
    Op          Op              `json:"op"`
    TS          time.Time       `json:"ts"`
    Payload     json.RawMessage `json:"payload,omitempty"`
    Deleted     bool            `json:"deleted,omitempty"`
    BaseVersion int64           `json:"base_version,omitempty"` // NEW: version this change was based on
}
```

### Conflict Detection Logic

When applying a pulled change:
1. Look up local record for `(entity, entity_id)`
2. If local `version > change.BaseVersion`, conflict detected
3. Options: (a) keep local, (b) accept remote, (c) create conflict copy
4. For v2, surface warning and let user decide via CLI flag

---

## 3. Snapshots & Compaction

### Problem
The `changes` table grows unbounded. New devices must replay entire history.

### Solution
Periodic snapshots capture full state. Changes before snapshot can be pruned.

### Schema Change (Server-side)

```sql
CREATE TABLE snapshots (
  snapshot_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  entity TEXT NOT NULL,              -- e.g., "todo", "notes"
  created_at INTEGER NOT NULL,
  min_seq INTEGER NOT NULL,          -- changes with seq <= this are represented in snapshot
  nonce_b64 TEXT NOT NULL,
  ct_b64 TEXT NOT NULL               -- encrypted: JSON array of all records for this entity
);
CREATE INDEX idx_snapshots_user_entity ON snapshots(user_id, entity, created_at DESC);
```

### Pull Logic Update

```
GET /v1/sync/pull?user_id=X&since=Y&entity=Z

If since == 0:
  1. Return latest snapshot for (user_id, entity) if exists
  2. Return changes where seq > snapshot.min_seq
Else:
  Return changes where seq > since (current behavior)
```

### Snapshot Creation

- Endpoint: `POST /v1/sync/snapshot` (authenticated)
- Client sends encrypted snapshot blob for each entity
- Server stores and updates `min_seq`
- Background job (or manual trigger) prunes changes older than oldest active snapshot

### Compaction

```sql
-- Prune changes that are fully represented in snapshots
DELETE FROM changes
WHERE user_id = ?
  AND entity = ?
  AND seq <= (SELECT min_seq FROM snapshots WHERE user_id = ? AND entity = ? ORDER BY created_at DESC LIMIT 1);
```

---

## 4. Background Cleanup

### Problem
Expired tokens and challenges accumulate forever.

### Solution
Background goroutine purges expired records hourly.

### Implementation

```go
func (s *Server) startCleanupRoutine() {
    go func() {
        ticker := time.NewTicker(1 * time.Hour)
        for range ticker.C {
            now := time.Now().Unix()
            s.db.Exec(`DELETE FROM tokens WHERE expires_at < ?`, now)
            s.db.Exec(`DELETE FROM challenges WHERE expires_at < ?`, now)
            log.Printf("cleanup: purged expired tokens and challenges")
        }
    }()
}
```

Call `s.startCleanupRoutine()` in `main()` after migration.

---

## 5. Rate Limiting

### Problem
No protection against runaway clients or abuse.

### Solution
In-memory token bucket rate limiter per user_id.

### Implementation

```go
import "golang.org/x/time/rate"

type Server struct {
    db        *sql.DB
    pbClient  pocketbase.Client
    limiters  sync.Map // user_id -> *rate.Limiter
}

func (s *Server) getLimiter(userID string) *rate.Limiter {
    if v, ok := s.limiters.Load(userID); ok {
        return v.(*rate.Limiter)
    }
    // ~100 requests/minute, burst of 10
    limiter := rate.NewLimiter(rate.Every(600*time.Millisecond), 10)
    s.limiters.Store(userID, limiter)
    return limiter
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        userID, err := s.authUser(r)
        if err != nil {
            fail(w, http.StatusUnauthorized, err.Error())
            return
        }

        limiter := s.getLimiter(userID)
        if !limiter.Allow() {
            fail(w, http.StatusTooManyRequests, "rate limit exceeded")
            return
        }

        ctx := context.WithValue(r.Context(), ctxUserIDKey{}, userID)
        next(w, r.WithContext(ctx))
    }
}
```

### Configuration
Rate limit configurable via environment variable `RATE_LIMIT_PER_MIN` (default: 100).

---

## 6. Seed Rotation

### Problem
No recovery path if seed phrase is compromised.

### Solution
Client-side re-encryption with new seed, server migration endpoint to transfer account.

### New CLI Command

```
sweet rotate-seed [--new-seed <phrase>]

1. Authenticate with current credentials
2. Pull all data, decrypt with current keys
3. Generate (or accept) new seed phrase
4. Derive new keys (new user_id)
5. Re-encrypt all data with new keys
6. Call POST /v1/account/migrate to transfer PocketBase account
7. Push all data under new user_id
8. Confirm and delete old user_id data
```

### Server Endpoint

```
POST /v1/account/migrate
Authorization: Bearer <token-for-old-user>

{
  "old_user_id": "abc123",
  "new_user_id": "def456",
  "confirm": true
}

Response: { "ok": true, "migrated_devices": 2 }
```

### Migration Logic

1. Verify token belongs to `old_user_id`
2. Call PocketBase to update `user_id` field on account record
3. Update `devices.user_id` from old to new
4. Optionally: delete old changes (or leave for grace period)
5. Invalidate all tokens for `old_user_id`

---

## Migration Path

### Database Migrations

Version the schema with a `schema_version` table:

```sql
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);
```

Migration sequence:
1. v1 -> v2: Create `devices` table, migrate existing `users.ssh_pubkey` to devices
2. v2 -> v3: Create `snapshots` table
3. Client-side: Add `version` column to `records`

### Backward Compatibility

- Old clients continue to work until they re-register (device table is additive)
- New pull endpoint accepts `since=0` for snapshot-based sync
- Conflict detection is opt-in (clients that don't send `base_version` get current behavior)

---

## Testing Requirements

1. **Multi-device**: Test registering 3 devices, revoking middle one, auth still works for others
2. **Conflict detection**: Two devices edit same entity offline, sync, verify conflict surfaced
3. **Snapshots**: Create snapshot, prune old changes, new device bootstraps from snapshot
4. **Cleanup**: Insert expired tokens, wait for cleanup cycle, verify deleted
5. **Rate limiting**: Burst 20 requests rapidly, verify 429 after limit
6. **Seed rotation**: Full rotation flow with data preservation verification

---

## Open Questions

1. **Snapshot frequency**: Client-triggered vs server-scheduled vs hybrid?
2. **Conflict UI**: How should CLI present conflicts? Interactive prompt vs flag?
3. **Device limits**: Cap devices per user? (suggest: 10)
4. **Rate limit scope**: Per-user or per-device?

---

## Summary

| Gap | Solution | Complexity |
|-----|----------|------------|
| Multi-device auth | `devices` table | Medium |
| Conflict resolution | Version tracking + detection | Medium |
| Data retention | Snapshots + pruning | High |
| Cleanup | Background goroutine | Low |
| Rate limiting | In-memory token bucket | Low |
| Key rotation | Client re-encryption + migrate endpoint | High |

Estimated implementation: 6 focused tasks, can be done incrementally.
