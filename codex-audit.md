# Suite Sync Audit

**Date:** 2025-02-15
**Scope:** Desktop CLIs (`cmd/internal/appcli`, `cmd/sweet`), shared vault crypto package, and the PocketBase-backed `syncvaultd` server with an emphasis on cryptography, feasibility, and security.

## Findings

### 1. [High] CLIs encrypt with a different `userID` than they use for sync (AAD mismatch)
- **Status:** Fixed
- **Evidence:** `cmd/internal/appcli/appcli.go:166-215` now requires `opts.UserID` before queueing changes and uses that same identifier for both `change.AAD` and the call to `vault.Sync`. This keeps encryption/decryption AAD in lockstep with the server routing identifier.
- **Impact:** Prior to the fix, devices using PocketBase IDs for sync but seed-derived IDs for encryption could not decrypt each other's envelopes. The new plumbing restores multi-device feasibility because every call site uses a single identifier consistently.
- **Recommendation:** None—continue to keep `opts.UserID` authoritative for encryption, queueing, and sync. Tests covering mixed-userID regressions would provide early warning if this regresses.

### 2. [High] Registration leaks verification tokens and bypasses email verification
- **Status:** Fixed
- **Evidence:** `cmd/syncvaultd/auth.go:100-146` now requires clients to supply a `device_id` during register/login, saves the device, and `withAuth` rejects tokens belonging to unverified PocketBase accounts (`cmd/syncvaultd/main.go:166-174`). As a result, the 24-hour token returned by `/v1/auth/pb/register` cannot be used until the email is verified. Token issuance still happens immediately, but all protected endpoints enforce verification.
- **Impact:** Unverified accounts can no longer sync or call protected APIs, closing the bypass. Tokens minted during register are inert until the mailbox is confirmed.
- **Recommendation:** None. Consider surfacing a clearer client error when verification is pending so UX knows why sync failed.

### 3. [Medium] Rate limiting trusts attacker-controlled headers
- **Status:** Fixed
- **Evidence:** `cmd/syncvaultd/ratelimit.go:90-120` now ignores `X-Forwarded-For`/`X-Real-IP` unless `TRUSTED_PROXY=1`. By default the limiter derives the key from `RemoteAddr`, so unauthenticated clients cannot spoof headers to reset their buckets.
- **Impact:** Auth endpoint throttling can no longer be bypassed simply by setting custom headers, restoring the intended protection against brute-force and account creation floods.
- **Recommendation:** Document the `TRUSTED_PROXY` knob (and expected proxy behavior) so operators understand when to enable header trust.

### 4. [Medium] “Device revocation” does not revoke anything
- **Status:** Fixed
- **Evidence:** Every authenticated request must now include `X-Vault-Device-ID`; `withAuth` (`cmd/syncvaultd/main.go:120-150`) validates the header against the `sync_devices` table and updates `last_used_at`. Register/login API calls require a `device_id` and register the device (`cmd/syncvaultd/auth.go:20-146`). Revocations move the device into the new `revoked_devices` collection (`cmd/syncvaultd/migrations/collections.go:34-57`, `cmd/syncvaultd/devices.go:67-147`), remove it from `sync_devices`, and further attempts to push/pull with that `device_id` fail because `withAuth` rejects unregistered devices. The server no longer auto-creates devices during push, and per-item device IDs are allowed only for devices still registered (`cmd/syncvaultd/main.go:214-229`). Clients send the header via `vault.Client` (`vault/client_http.go:18-178`).
- **Impact:** Revoking a device now blocks future syncs from that device ID—even if the attacker still has the JWT token—until the user re-registers through a verified login. Pushes that spoof other device IDs must first register those devices by completing auth, and `/v1/devices/:id` refuses to delete the device currently making the request.
- **Recommendation:** Consider surfacing revoked devices in `GET /v1/devices` or via a dedicated endpoint, since revoked entries are now tracked separately.

### 5. [High] Sequence generator silently resets to `1` on DB errors (data loss)
- **Status:** Fixed
- **Evidence:** `getNextSeqTx` in `cmd/syncvaultd/main.go:307-316` now returns an error when the PocketBase query fails rather than defaulting to `1`. `insertChanges` propagates that error so the client retries instead of inserting duplicate sequence numbers.
- **Impact:** Transient DB failures no longer corrupt the sequence log; clients will encounter a recoverable push error instead of silently losing change history.
- **Recommendation:** Consider metrics/alerts on repeated `db error` responses so operators can investigate underlying PocketBase instability.

---

Please reach out if you would like help addressing the outstanding issues or re-running the audit after additional patches.
