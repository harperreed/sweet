# Suite Sync

Suite Sync packages an encrypted sync core (`vault/`), three example CLIs (`todo`, `notes`, and `logger`), and a tiny HTTP server (`cmd/syncvaultd`). The CLI binaries keep their own SQLite tables but rely on the shared vault library for key derivation, encryption, change tracking, and HTTP sync.

## Layout

```
vault/               # shared Go module
cmd/internal/appcli  # helper glue for entity CLIs
cmd/auth             # helper CLI to register/login via SSH key
cmd/todo             # todo manager CLI
cmd/notes            # note taker CLI
cmd/logger           # append-only logger CLI
cmd/sweet            # end-user introspection CLI
cmd/syncvaultd       # minimal sync server
Dockerfile           # Fly/containers
```

## Library

The `vault` package exposes:

- `SeedPhrase`, `DeriveKeys`, and `KDFParams` for deterministic key derivation.
- `Encrypt`/`Decrypt` helpers plus `Change`/`Op` definitions.
- `Store` (SQLite) for the encrypted outbox/state.
- `Client`/`Sync` for HTTP push/pull.

Import it from other Go programs:

```go
store, _ := vault.OpenStore("/tmp/vault.db")
keys, _ := vault.DeriveKeys(seed, "", vault.DefaultKDFParams())
client := vault.NewClient(vault.SyncConfig{BaseURL: "https://sync.example", DeviceID: "laptop", AuthToken: token})
_ = vault.Sync(ctx, store, client, keys, applyFn)
```

## CLIs

Each CLI shares the same flags:

```
-seed       hex seed phrase
-passphrase optional passphrase mixed into the key derivation
-vault-db   path to encrypted outbox db (default: ./<entity>_vault.db)
-app-db     path to app data db (default: ./<entity>.db)
-device     stable device identifier (default: hostname)
-server     sync server base URL (e.g. https://sync.yourapp.com)
-token      bearer token issued by the server
```

Example todo session:

```sh
# Generate a seed (store it somewhere safe!)
$ go run ./cmd/todo seed
8bb630...

# Create a todo offline
$ go run ./cmd/todo upsert -seed 8bb630... -id 123 -text "write docs"

# Sync with server using device+token
$ go run ./cmd/todo sync -seed 8bb630... -server https://syncvault.fly.dev -token $(cat token.txt)
```

The `notes` binary works identically with `-title/-body`, while `logger` exposes `append` to emit new log entries with `-message/-level`.

### SSH auth helper

`cmd/auth` automates the register/challenge/verify dance against the server:

```
# Register or refresh your SSH key for the derived user_id
$ go run ./cmd/auth register -server https://syncvault.fly.dev -user <user_id> -key ~/.ssh/id_ed25519

# Login and print/save a bearer token (auto-register if missing)
$ go run ./cmd/auth login -server https://syncvault.fly.dev -user <user_id> -register -out token.txt
```

`user_id` comes from `vault.Keys.UserID()` (exposed via your CLIs); the login command signs challenges with your SSH private key and returns a bearer token you can pass to other CLIs via `-token`.

### Sweet introspection CLI

`cmd/sweet` lets end users peek into their local SQLite store without juggling multiple CLIs.

```
# Show record counts per entity
$ go run ./cmd/sweet summary -app-db ~/.suite/suite.db

# Pretty-print the latest todos (adjust entity to note/log/etc.)
$ go run ./cmd/sweet list -entity todo -app-db ~/.suite/suite.db -limit 5
```

The tool operates entirely on the decrypted `records` table, so no seed/passphrase is required—just point it at the same `-app-db` path the other CLIs use.

### Sweet register/login (PocketBase + SSH)

For Atuin-style onboarding, `sweet` also includes account helpers backed by PocketBase:

```
# Register a new account, generate a seed phrase, and upload your SSH public key
$ go run ./cmd/sweet register \
    -pb-url https://accounts.example.com \
    -server https://syncvault.fly.dev \
    -username alice -password 's3cret!' \
    -key ~/.ssh/id_ed25519

# Later on another device, authenticate with username/password + seed phrase and mint a sync token
$ go run ./cmd/sweet login \
    -pb-url https://accounts.example.com \
    -server https://syncvault.fly.dev \
    -username alice -password 's3cret!' \
    -seed <seed phrase from register> \
    -key ~/.ssh/id_ed25519
```

PocketBase handles username/password UX, quotas, and billing, while the sync server still relies on SSH keys + the seed-derived `user_id` for end-to-end encryption.

## Server

Run the server locally via Go:

```sh
$ go run ./cmd/syncvaultd -addr :8080 -db ./syncvault.sqlite
```

Endpoints:

- `POST /v1/auth/register` with `{user_id, ssh_pubkey_openssh}`.
- `POST /v1/auth/challenge` → `{challenge_id, challenge_b64}`.
- `POST /v1/auth/verify` with signed challenge → bearer `{token}`.
- `POST /v1/sync/push` and `GET /v1/sync/pull` for encrypted envelopes.

The server stores only `{nonce, ciphertext}` and device/entity metadata.

### PocketBase control plane

If you want username/password onboarding, point the server at a PocketBase instance:

```
export POCKETBASE_URL=https://accounts.example.com
export POCKETBASE_ADMIN_TOKEN=<admin API token>
```

When these variables are set:

- `sweet register/login` talk to PocketBase to create/login accounts while the sync server still requires SSH keys + seed phrases.
- Every `/v1/auth/verify` call checks that the PocketBase account is active before issuing a bearer token.
- `/v1/sync/push` updates usage counters via the PocketBase REST hook (`/api/hooks/usage`), so you can enforce plans/quotas centrally.

Leave the variables unset to run the server in “standalone” mode (SSH auth only).

## Fly.io deployment

A ready-to-use `Dockerfile` builds a static linux binary. The included `fly.toml` example mounts a volume so SQLite sticks around. Steps:

```sh
$ fly launch --name suite-sync --no-deploy
$ fly volumes create vault_data --size 1 --region iad
$ fly secrets set ADDR=0.0.0.0:8080 DB_PATH=/data/syncvault.sqlite
$ fly deploy
```

`fly deploy` automatically builds the container using the `Dockerfile`. Traffic hits port 8080 and the volume is mounted at `/data` per `fly.toml`.

## Tests / lint

Run `go test ./...` to ensure the code compiles; integration coverage in `cmd/syncvaultd/main_test.go` spins up the server against a temp SQLite DB, exercises SSH auth, and validates encrypted push/pull across two devices.
