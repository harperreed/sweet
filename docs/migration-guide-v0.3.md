# Migration Guide: v0.2.x to v0.3.0

This guide covers the breaking changes in v0.3.0 related to device validation security improvements.

## Overview

v0.3.0 introduces mandatory device validation based on the security audit findings. All authenticated API requests now require:

1. A registered device ID
2. The `X-Vault-Device-ID` header on every request

This change provides per-device access control and revocation capabilities.

## Breaking Changes

### 1. Device ID Required in SyncConfig

**Before (v0.2.x):**
```go
client := vault.NewClient(vault.SyncConfig{
    BaseURL:   "https://api.storeusa.org",
    AuthToken: token,
})
```

**After (v0.3.0):**
```go
client := vault.NewClient(vault.SyncConfig{
    BaseURL:   "https://api.storeusa.org",
    DeviceID:  deviceID,  // REQUIRED - panics if empty
    AuthToken: token,
})
```

### 2. Device Registration at Login/Register

**Before (v0.2.x):**
```go
result, err := authClient.Login(ctx, email, password)
```

**After (v0.3.0):**
```go
result, err := authClient.LoginWithDevice(ctx, email, password, deviceID)
```

The server now requires `device_id` in login/register request bodies:
```json
{
  "email": "user@example.com",
  "password": "...",
  "device_id": "01JFXYZ..."
}
```

### 3. X-Vault-Device-ID Header

All authenticated endpoints now require the header:
```
X-Vault-Device-ID: <device-id>
```

The vault client library adds this automatically when `DeviceID` is set.

**Raw HTTP requests must include:**
```go
req.Header.Set("X-Vault-Device-ID", deviceID)
```

### 4. Error Responses

New error responses you may encounter:

| Status | Error | Cause |
|--------|-------|-------|
| 400 | `device id header required` | Missing `X-Vault-Device-ID` header |
| 403 | `device not registered` | Device ID not in `sync_devices` table |
| 403 | `device not registered for this user` | Device belongs to different user |
| 403 | `device has been revoked` | Device was previously revoked |

## Migration Steps

### Step 1: Update Your Config Struct

Add `DeviceID` field if not already present:

```go
type Config struct {
    Server       string `json:"server"`
    UserID       string `json:"user_id"`
    Token        string `json:"token"`
    DeviceID     string `json:"device_id"`  // ADD THIS
    // ... other fields
}
```

### Step 2: Generate Device ID on First Run

```go
import "github.com/oklog/ulid/v2"

func ensureDeviceID(cfg *Config) error {
    if cfg.DeviceID != "" {
        return nil  // Already have one
    }
    cfg.DeviceID = ulid.Make().String()
    return SaveConfig(cfg)
}
```

### Step 3: Update Login/Register Flow

```go
func login(server, email, password, mnemonic string) error {
    cfg, _ := LoadConfig()

    // Ensure we have a device ID before login
    if cfg.DeviceID == "" {
        cfg.DeviceID = ulid.Make().String()
    }

    client := vault.NewPBAuthClient(server)

    // Use LoginWithDevice instead of Login
    result, err := client.LoginWithDevice(ctx, email, password, cfg.DeviceID)
    if err != nil {
        return err
    }

    // Save config with device ID
    cfg.Token = result.Token.Token
    cfg.UserID = result.UserID
    return SaveConfig(cfg)
}
```

### Step 4: Update Client Creation

```go
func NewSyncer(cfg *Config) (*Syncer, error) {
    if cfg.DeviceID == "" {
        return nil, fmt.Errorf("device ID required - run login again")
    }

    client := vault.NewClient(vault.SyncConfig{
        BaseURL:   cfg.Server,
        DeviceID:  cfg.DeviceID,
        AuthToken: cfg.Token,
    })
    // ...
}
```

### Step 5: Handle Migration for Existing Users

Users with existing configs (no device ID) need to re-authenticate:

```go
func (s *Syncer) Sync(ctx context.Context) error {
    // Check for device-related errors
    err := vault.Sync(ctx, s.store, s.client, s.keys, s.userID, s.apply)
    if err != nil {
        if strings.Contains(err.Error(), "device") ||
           strings.Contains(err.Error(), "403") {
            return fmt.Errorf("device not registered - please run 'yourapp sync login' again: %w", err)
        }
    }
    return err
}
```

## Device Management

### List Devices

```bash
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-Vault-Device-ID: $DEVICE_ID" \
     https://api.storeusa.org/v1/devices
```

Response:
```json
{
  "devices": [
    {"device_id": "01JFX...", "name": "macbook", "last_used_at": 1702000000},
    {"device_id": "01JFY...", "name": "iphone", "last_used_at": 1702001000}
  ]
}
```

### Revoke a Device

```bash
curl -X DELETE \
     -H "Authorization: Bearer $TOKEN" \
     -H "X-Vault-Device-ID: $DEVICE_ID" \
     https://api.storeusa.org/v1/devices/01JFY...
```

**Note:** You cannot revoke the device you're currently using.

### Revoked Devices Cannot Re-register

Once revoked, a device ID is permanently blocked for that user. The user must use a new device ID.

## Checklist

- [ ] Add `DeviceID` to config struct
- [ ] Generate stable device ID (ULID recommended)
- [ ] Update login to use `LoginWithDevice`
- [ ] Update `vault.NewClient` to include `DeviceID`
- [ ] Handle 403 errors with helpful re-login message
- [ ] Test: fresh login registers device
- [ ] Test: sync works with registered device
- [ ] Test: sync fails with unregistered device (403)

## FAQ

### Q: What if my users have existing tokens without device registration?

They will get 403 errors on sync. Guide them to re-run login, which will register their device.

### Q: Can I use the same device ID across reinstalls?

Yes, if you persist it. The device ID should be stable per-device. Store it in your config file.

### Q: What happens to tokens after device revocation?

JWT tokens remain technically valid, but all API calls will fail because the device is no longer registered.

### Q: How do I migrate server-side data?

No server-side migration needed. Device validation is enforced at the API layer. Existing data remains intact.

### Q: Can a device be un-revoked?

No. Once revoked, that device ID is permanently blocked. Generate a new device ID and re-login.
