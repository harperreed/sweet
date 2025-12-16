# App Tokens Design

App tokens provide long-lived authentication for CI/CD and automation use cases.

## Problem

Current auth tokens expire in 24 hours. CI jobs (like GitHub Actions pushing health data) need stable credentials that don't require interactive login or token refresh.

## Solution

Add "app tokens" - long-lived JWTs that don't expire but can be revoked.

## Data Model

**`app_tokens` collection:**

| Field | Type | Description |
|-------|------|-------------|
| id | string | PocketBase auto-generated |
| token_id | string | Unique identifier embedded in JWT (e.g., `apt_abc123`) |
| name | string | User-provided label (e.g., "github-actions") |
| user | relation | Reference to users collection |
| revoked | boolean | Whether token has been revoked |
| created | datetime | Auto-managed by PocketBase |
| updated | datetime | Used as "last_used" timestamp |

Index on `token_id` for fast lookups.

## API Endpoints

### Create App Token

`POST /v1/auth/app-token`

```json
// Request (email/password auth)
{
  "email": "user@example.com",
  "password": "...",
  "name": "github-actions"
}

// Response
{
  "app_token": "eyJhbG...",
  "token_id": "apt_abc123",
  "name": "github-actions",
  "user_id": "user123",
  "created": "2024-12-15T10:00:00Z"
}
```

### List App Tokens

`GET /v1/auth/app-tokens` (requires auth)

```json
{
  "tokens": [
    {
      "token_id": "apt_abc123",
      "name": "github-actions",
      "created": "2024-12-15T10:00:00Z",
      "last_used": "2024-12-16T03:00:00Z",
      "revoked": false
    }
  ]
}
```

### Revoke App Token

`DELETE /v1/auth/app-tokens/:token_id` (requires auth)

```json
{"ok": true, "revoked": "apt_abc123"}
```

## JWT Structure

App tokens are standard PocketBase JWTs with an additional `token_id` claim:

```json
{
  "id": "user123",
  "type": "auth",
  "token_id": "apt_abc123",
  "exp": 0  // No expiration
}
```

The `token_id` claim distinguishes app tokens from regular session tokens.

## Auth Flow

```go
func (s *Server) authUserJWT(token string) (authInfo, error) {
    // 1. Validate JWT signature and get user (existing)
    userRecord, err := s.app.FindAuthRecordByToken(token, core.TokenTypeAuth)
    if err != nil {
        return authInfo{}, errors.New("invalid token")
    }

    // 2. Check if this is an app token (has token_id claim)
    tokenID := extractTokenID(token)
    if tokenID != "" {
        // 3. Look up in app_tokens collection
        appToken, err := s.findAppToken(tokenID)
        if err != nil {
            return authInfo{}, errors.New("app token not found")
        }
        if appToken.GetBool("revoked") {
            return authInfo{}, errors.New("app token revoked")
        }
        // 4. Update last_used timestamp (async)
        go s.updateAppTokenLastUsed(tokenID)
    }

    return authInfo{userID: userRecord.Id, deviceID: ""}, nil
}
```

Regular session tokens (no `token_id` claim) skip revocation check - zero overhead.

## CLI Commands

### Create

```bash
$ sweet sync app-token create --name "github-actions"
Enter password for user@example.com: ********

App token created successfully!

  Token ID:  apt_7xk2m9
  Name:      github-actions

  App Token (save this - it won't be shown again):
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Add to GitHub secrets:
  SYNC_APP_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  SYNC_DERIVED_KEY=<your hex-encoded seed from ~/.config/sweet/sync.json>
```

### List

```bash
$ sweet sync app-token list

NAME              TOKEN ID      CREATED       LAST USED     STATUS
github-actions    apt_7xk2m9    2024-12-15    2024-12-16    active
old-ci            apt_3nm8x2    2024-01-01    2024-06-15    active
```

### Revoke

```bash
$ sweet sync app-token revoke apt_7xk2m9
Revoked app token: github-actions (apt_7xk2m9)
```

## Usage in GitHub Actions

```yaml
name: Sync Health Data

on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6am

jobs:
  sync:
    runs-on: ubuntu-latest
    env:
      SYNC_APP_TOKEN: ${{ secrets.SYNC_APP_TOKEN }}
      SYNC_DERIVED_KEY: ${{ secrets.SYNC_DERIVED_KEY }}
      SYNC_SERVER: https://api.storeusa.org

    steps:
      - name: Push health data
        run: |
          # App token works with existing client - no changes needed
          ./health-sync push --token "$SYNC_APP_TOKEN" --key "$SYNC_DERIVED_KEY"
```

## Implementation Tasks

1. **Migration**: Create `app_tokens` collection
2. **Server endpoints**: `/v1/auth/app-token`, `/v1/auth/app-tokens`, `/v1/auth/app-tokens/:id`
3. **Auth middleware**: Add token_id extraction and revocation check
4. **CLI commands**: `sweet sync app-token create/list/revoke`
5. **Documentation**: Update integration guide

## Security Considerations

- App tokens never expire - revocation is the only way to invalidate
- Token displayed only once at creation - user must save it securely
- Revoked tokens are kept in DB (soft delete) for audit trail
- Rate limiting applies to app tokens same as regular tokens

## Client Changes

None required. App tokens are standard JWTs that work with existing `AuthToken` field.
