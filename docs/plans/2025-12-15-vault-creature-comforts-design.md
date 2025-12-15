# Vault Creature Comforts Design

**Date:** 2025-12-15
**Status:** Approved
**Author:** Claude + Harper

## Overview

Add robustness features to the vault library that make client applications more resilient and observable. These "creature comforts" handle common pain points: token expiry, network flakiness, and lack of visibility into sync state.

## Features

### 1. Typed Errors

**Problem:** All errors are strings. Clients can't programmatically distinguish between token expiry, network failure, and conflicts.

**Solution:** Define sentinel errors and a `SyncError` wrapper.

```go
// vault/errors.go

var (
    ErrTokenExpired   = errors.New("token expired")
    ErrUnauthorized   = errors.New("unauthorized")
    ErrNetworkFailure = errors.New("network failure")
    ErrServerError    = errors.New("server error")
    ErrConflict       = errors.New("conflict detected")
    ErrNotConfigured  = errors.New("sync not configured")
)

type SyncError struct {
    Op      string // "push", "pull", "refresh"
    Err     error  // underlying typed error
    Retries int    // attempts made
    Detail  string // server message if any
}

func (e *SyncError) Error() string {
    return fmt.Sprintf("%s failed after %d attempts: %v", e.Op, e.Retries, e.Err)
}

func (e *SyncError) Unwrap() error { return e.Err }
```

**Usage:**
```go
if errors.Is(err, vault.ErrTokenExpired) {
    // trigger re-login
}
```

### 2. Retry with Exponential Backoff

**Problem:** Network failures cause immediate sync failure. Transient issues aren't retried.

**Solution:** Wrap HTTP calls with configurable retry logic.

```go
// vault/retry.go

type RetryConfig struct {
    MaxAttempts int           // default: 3
    InitialWait time.Duration // default: 500ms
    MaxWait     time.Duration // default: 30s
    Multiplier  float64       // default: 2.0
}

func DefaultRetryConfig() RetryConfig {
    return RetryConfig{
        MaxAttempts: 3,
        InitialWait: 500 * time.Millisecond,
        MaxWait:     30 * time.Second,
        Multiplier:  2.0,
    }
}

func retryable(err error) bool {
    if err == nil {
        return false
    }
    return errors.Is(err, ErrNetworkFailure) || errors.Is(err, ErrServerError)
}

func withRetry[T any](ctx context.Context, cfg RetryConfig, op string, fn func() (T, error)) (T, error) {
    var zero T
    wait := cfg.InitialWait

    for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
        result, err := fn()
        if err == nil {
            return result, nil
        }
        if !retryable(err) || attempt == cfg.MaxAttempts {
            return zero, &SyncError{Op: op, Err: err, Retries: attempt}
        }

        select {
        case <-ctx.Done():
            return zero, ctx.Err()
        case <-time.After(wait):
        }

        wait = time.Duration(float64(wait) * cfg.Multiplier)
        if wait > cfg.MaxWait {
            wait = cfg.MaxWait
        }
    }
    return zero, &SyncError{Op: op, Err: ErrNetworkFailure, Retries: cfg.MaxAttempts}
}
```

### 3. Automatic Token Refresh

**Problem:** Tokens expire. Clients must manually detect expiry and call Refresh(). Expired tokens cause silent sync failures.

**Solution:** Client auto-refreshes before expiry, with callback to persist new tokens.

```go
// vault/config.go - extend SyncConfig

type SyncConfig struct {
    BaseURL      string
    DeviceID     string
    AuthToken    string
    RefreshToken string           // for auto-refresh
    TokenExpires time.Time        // when current token expires
    Timeout      time.Duration
    Retry        RetryConfig      // retry settings

    // OnTokenRefresh is called when tokens are refreshed.
    // Client should persist the new tokens.
    OnTokenRefresh func(token, refreshToken string, expires time.Time)
}
```

```go
// vault/client_http.go

func (c *Client) ensureValidToken(ctx context.Context) error {
    // Refresh if token expires within 5 minutes
    if time.Until(c.cfg.TokenExpires) > 5*time.Minute {
        return nil
    }
    if c.cfg.RefreshToken == "" {
        return ErrTokenExpired
    }

    auth := NewPBAuthClient(c.cfg.BaseURL)
    result, err := auth.Refresh(ctx, c.cfg.RefreshToken)
    if err != nil {
        return fmt.Errorf("%w: %v", ErrTokenExpired, err)
    }

    c.cfg.AuthToken = result.Token.Token
    c.cfg.RefreshToken = result.RefreshToken
    c.cfg.TokenExpires = result.Token.Expires

    if c.cfg.OnTokenRefresh != nil {
        c.cfg.OnTokenRefresh(result.Token.Token, result.RefreshToken, result.Token.Expires)
    }
    return nil
}
```

Push and Pull call `ensureValidToken()` before making requests.

### 4. Observability (Pending Count + Sync Events)

**Problem:** Clients have no visibility into sync state. Can't show "3 changes pending" or progress during sync.

**Solution:** Add status queries and event hooks.

```go
// vault/store_sqlite.go

func (s *Store) PendingCount(ctx context.Context) (int, error) {
    var count int
    err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&count)
    return count, err
}

type SyncStatus struct {
    PendingChanges int
    LastPulledSeq  int64
}

func (s *Store) SyncStatus(ctx context.Context) (SyncStatus, error) {
    pending, err := s.PendingCount(ctx)
    if err != nil {
        return SyncStatus{}, err
    }
    seqStr, _ := s.GetState(ctx, "last_pulled_seq", "0")
    seq, _ := strconv.ParseInt(seqStr, 10, 64)

    return SyncStatus{
        PendingChanges: pending,
        LastPulledSeq:  seq,
    }, nil
}
```

```go
// vault/sync.go

type SyncEvents struct {
    OnStart    func()
    OnPush     func(pushed, remaining int)
    OnPull     func(pulled int)
    OnComplete func(pushed, pulled int)
    OnError    func(err error)
}

func Sync(ctx context.Context, store *Store, client *Client, keys Keys, userID string, apply ApplyFn, events *SyncEvents) error {
    if events != nil && events.OnStart != nil {
        events.OnStart()
    }

    totalPushed, err := pushOutboxWithEvents(ctx, store, client, userID, events)
    if err != nil {
        if events != nil && events.OnError != nil {
            events.OnError(err)
        }
        return err
    }

    totalPulled, err := pullWithEvents(ctx, store, client, keys, userID, apply, events)
    if err != nil {
        if events != nil && events.OnError != nil {
            events.OnError(err)
        }
        return err
    }

    if events != nil && events.OnComplete != nil {
        events.OnComplete(totalPushed, totalPulled)
    }
    return nil
}
```

### 5. Health Check

**Problem:** No way to verify server connectivity before attempting sync.

**Solution:** Add health endpoint and client method.

```go
// vault/client_http.go

type HealthStatus struct {
    OK           bool
    Latency      time.Duration
    ServerTime   time.Time
    TokenValid   bool
    TokenExpires time.Time
}

func (c *Client) Health(ctx context.Context) HealthStatus {
    start := time.Now()
    status := HealthStatus{
        TokenExpires: c.cfg.TokenExpires,
        TokenValid:   time.Until(c.cfg.TokenExpires) > 0,
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/v1/health", nil)
    if err != nil {
        return status
    }
    req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)

    resp, err := c.hc.Do(req)
    if err != nil {
        return status
    }
    defer resp.Body.Close()

    status.Latency = time.Since(start)
    status.OK = resp.StatusCode == http.StatusOK

    var body struct {
        Time int64 `json:"time"`
    }
    if json.NewDecoder(resp.Body).Decode(&body) == nil {
        status.ServerTime = time.Unix(body.Time, 0)
    }

    return status
}
```

**Server endpoint (syncvaultd):**
```go
// GET /v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(map[string]any{
        "ok":   true,
        "time": time.Now().Unix(),
    })
}
```

## File Changes

| File | Change |
|------|--------|
| `vault/errors.go` | NEW - typed errors |
| `vault/retry.go` | NEW - retry logic |
| `vault/config.go` | Extend SyncConfig |
| `vault/client_http.go` | Add ensureValidToken, Health, wrap Push/Pull with retry |
| `vault/store_sqlite.go` | Add PendingCount, SyncStatus |
| `vault/sync.go` | Add SyncEvents parameter, refactor for events |
| `cmd/syncvaultd/main.go` | Add /v1/health endpoint |

## Breaking Changes

1. **`Sync()` signature changes** - Adds `*SyncEvents` parameter (pass `nil` for old behavior)
2. **`SyncConfig` has new fields** - Backward compatible (zero values work)

## Migration

Existing code continues to work:
```go
// Old code still works
vault.Sync(ctx, store, client, keys, userID, apply, nil)
```

New code can opt into features:
```go
// New code with events
vault.Sync(ctx, store, client, keys, userID, apply, &vault.SyncEvents{
    OnComplete: func(p, l int) { log.Printf("synced %d/%d", p, l) },
})
```

## Testing Strategy

1. **Unit tests** for each new file (errors, retry)
2. **Integration tests** for token refresh flow
3. **Mock server** for health check and retry behavior
4. **Existing tests** must continue to pass

## Implementation Order

1. `vault/errors.go` - foundation
2. `vault/retry.go` - standalone utility
3. `vault/config.go` - extend SyncConfig
4. `vault/client_http.go` - ensureValidToken, Health, retry wrapping
5. `vault/store_sqlite.go` - PendingCount, SyncStatus
6. `vault/sync.go` - SyncEvents integration
7. `cmd/syncvaultd` - /v1/health endpoint
8. Update integration guide
