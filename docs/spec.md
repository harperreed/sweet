# suite-sync Specification

## Overview

Suite Sync delivers end-to-end encrypted synchronization across several CLI utilities (`todo`, `notes`, `logger`). The system is composed of:

- A reusable Go module (`vault/`) that handles key derivation, change tracking, local persistence, and HTTP sync.
- Per-entity CLIs that manipulate local data and rely on `vault` for encryption and sync orchestration.
- A Go HTTP server (`cmd/syncvaultd`) that stores encrypted changes, verifies client identity, and exposes the push/pull API.
- A PocketBase-backed control plane that manages human-friendly accounts (username/password), quotas, and billing metadata.
- The `sweet` CLI, which provides end-user introspection (listing records) and wraps the PocketBase + SSH onboarding flow.

All user content is encrypted client-side. The server only stores `(nonce, ciphertext)` envelopes plus minimal metadata (user ID, device ID, entity, timestamps).

## Vault Library (`vault/`)

### Key Derivation and Seeds

- `SeedPhrase` is a 32-byte seed represented as a hex string (placeholder for future BIP-39 support).
- `DeriveKeys` mixes the seed + optional passphrase via Argon2id (configurable `KDFParams`) and expands the result into:
  - `EncKey` (32-byte XChaCha20-Poly1305 key)
  - `UserKey` (used to derive the stable `UserID` identifier)
- `Keys.UserID()` returns the deterministic ID sent to the server. The actual seed never leaves the client.

### Change Model

- `Change` is the logical mutation structure: `entity`, `entity_id`, `op`, timestamp, payload (`json.RawMessage`), and `change_id` (ULID).
- `Change.AAD(userID, deviceID)` produces deterministic associated data binding `userID`, `deviceID`, `change_id`, and `entity`. It is concatenated with the device ID during encryption to prevent replay/masquerade.

### Encryption

- `Encrypt` wraps XChaCha20-Poly1305 with random nonces. The plaintext is a JSON-encoded `Change`. AAD binds metadata as above.
- `Decrypt` reverses the process. If AAD mismatches, the decryption fails.

### Local Store

- `Store` (SQLite via `modernc.org/sqlite`) maintains:
  - `outbox`: encrypted envelopes awaiting push.
  - `sync_state`: monotonic sequence tracking (`last_pulled_seq`).
  - Note: `applied` table is present for future dedupe logic.
- Methods:
  - `EnqueueEncryptedChange` stores a change with its envelope.
  - `DequeueBatch(limit)` returns `OutboxItem`s (change ID, entity, timestamp, envelope).
  - `AckOutbox` deletes acknowledged changes.
  - `GetState` / `SetState` manage `last_pulled_seq`.

### HTTP Client

- `Client` takes `SyncConfig` (`BaseURL`, `DeviceID`, `AuthToken`, `Timeout`).
- `Push` posts `PushReq` with `user_id`, `device_id`, and `changes` (includes entity + timestamp for server AAD reconstruction).
- `Pull` fetches encrypted changes since the stored sequence number and returns `PullItem`s (seq, change ID, device, entity, envelope).

### Sync Loop

`vault.Sync` orchestrates:
1. Dequeues up to 200 outbox entries, wraps them in `PushItem`, calls `Client.Push`, and acknowledges on success.
2. Reads `last_pulled_seq`, runs `Client.Pull`, decrypts each envelope with `Change.AAD` semantics, passes to the caller-provided `ApplyFn`, and updates `last_pulled_seq`.

## Application CLIs

### Shared App Layer (`cmd/internal/appcli`)

- `App` encapsulates:
  - `vault.Store` for the encrypted queue.
  - `appDB` (SQLite) containing `records` (entity, entity_id, payload JSON, op, updated_at).
  - Derived `vault.Keys` and HTTP client.
- CRUD operations (`Upsert`, `Append`, `Delete`) write to `records`, create new `Change`s, encrypt them, and enqueue for sync.
- `Sync` delegates to `vault.Sync`, using `App.ApplyChange` to mutate `records`.
- Flags (seed, passphrase, vault DB path, app DB path, device ID, server URL, bearer token) are shared via `RuntimeConfig`.

### Entity CLIs

- `cmd/todo`, `cmd/notes`, `cmd/logger` call `appcli`. They expose commands:
  - `seed`: generate/store a new seed phrase.
  - `upsert`/`append`/`delete`: mutate records.
  - `list`: show local records.
  - `sync`: push/pull via the server (requires `-server`, `-token`, `-seed`).

## `sweet` CLI

### Introspection

- Uses `cmd/sweet/internal/inspect` to open the `records` table and provide:
  - `summary`: per-entity counts.
  - `list`: latest records for a given entity, pretty printing the JSON payload.

### PocketBase-Backed Register/Login

- `sweet register`:
  1. Calls PocketBase REST (`/api/collections/users/records`) with username/email/password, storing the deterministic `user_id`.
  2. Generates a new seed phrase and derives keys.
  3. Registers the user’s SSH public key with the sync server via `vault.AuthClient`.
  4. Outputs the seed phrase for safe storage.
- `sweet login`:
  1. Authenticates with PocketBase (`auth-with-password`) using username/password.
  2. Derives keys from the supplied seed phrase.
  3. Logs into the sync server with the SSH key (auto-registering per device if requested) and prints a bearer token.

PocketBase URL (`-pb-url`), sync server URL, and device SSH key path are configurable via flags. The CLI never sends the seed to the server.

## Sync Server (`cmd/syncvaultd`)

### HTTP Endpoints

- `POST /v1/auth/register`: stores `user_id` ↔ SSH public key/ fingerprint.
- `POST /v1/auth/challenge`: generates a challenge (random 32 bytes) for a user.
- `POST /v1/auth/verify`: verifies SSH signature over the challenge, issues a bearer token if PocketBase marks the account active.
- `POST /v1/sync/push`: stores encrypted envelopes (deduped by change ID), increments PocketBase usage counters.
- `GET /v1/sync/pull`: returns changes with monotonically increasing `seq`.
- `GET /healthz`: simple readiness probe.

### Storage

- SQLite (via `modernc.org/sqlite`) with WAL journaling to persist:
  - `users`: user ID, SSH key, fingerprint, created_at.
  - `challenges`: challenge bytes, expiry.
  - `tokens`: hashed bearer tokens (`sha256` of raw token), expiry.
  - `changes`: append-only log with `seq`, `user_id`, `change_id`, `device_id`, `entity`, `ts`, `nonce`, `ciphertext`.

### Auth Flow

1. Client calls `/v1/auth/register` to bind `user_id` (derived from seed) to an SSH public key.
2. Client requests a challenge, signs it with the private key, and sends the signature to `/v1/auth/verify`.
3. Server verifies:
   - PocketBase account (`GetAccountByUserID`) is active.
   - Challenge exists and is unexpired; signature matches.
   - Issues a token `sv_<random>` (stored hashed) valid for 12 hours.
4. Token is passed as `Authorization: Bearer <token>` on push/pull.

### PocketBase Integration

Configured via `POCKETBASE_URL` and `POCKETBASE_ADMIN_TOKEN`. If set, the server:

- Uses `internal/pocketbase.HTTPClient` to fetch account metadata per `user_id` before issuing tokens. Inactive or missing accounts cause `/v1/auth/verify` to fail.
- Calls `IncrementUsage(userID, changeCount)` after each successful `/v1/sync/push` to update quotas via PocketBase hook (`/api/hooks/usage`).
- Falls back to a `NoopClient` when environment variables are unset (pure SSH auth).

### Testing

`cmd/syncvaultd/main_test.go` includes:

- End-to-end sync using two devices and the server handler.
- PocketBase usage increment verification via a mock client.
- Inactive account failure on `/v1/auth/verify`.
- Helper functions to create the test DB, start the server, generate seed/keys, and login for tokens.

## Config and Deployment

- `Dockerfile`: two-stage build (Go 1.22, distroless runtime) producing a static `syncvaultd`.
- `fly.toml`: Fly.io configuration (port 8080, `/data` volume for SQLite, `ADDR`/`DB_PATH` env defaults). Set `POCKETBASE_*` env vars or secrets at deploy time to enable the hybrid flow.

## Security Model

- Encryption keys are derived entirely from the user’s seed phrase (and optional passphrase). The server never sees plaintext.
- SSH keys authenticate devices. Seed phrases should be stored securely; losing them means losing access to data.
- PocketBase captures only control-plane metadata (email, username, plan, usage stats). It does not contain decrypted data.

## Future Extensions (Notes)

- Swap the hex seed phrase for BIP-39 for user-friendliness.
- Implement an OAuth-capable PocketBase extension or Web UI.
- Add PAT (personal access tokens) managed via PocketBase for unattended syncing (e.g., CI jobs).
- Extend `sweet` to decrypt queued outbox entries before sync for better visibility.
