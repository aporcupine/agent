# `cmd/elevate`

Local privileged helper for temporary local-admin elevation.

## Overview

`elevate` is a standalone daemon that runs as root (or an equivalent privileged account) on Linux, macOS, and Windows. It listens on a local Unix domain socket for IPC requests, authenticates each request via a challenge-response protocol using Ed25519 signatures verified against compile-time pinned public keys, and performs OS-level privilege grant/revoke operations.

Grant state is persisted to a single versioned JSON file using atomic writes (`tmp` → `fsync` → `rename` → `dir fsync`) with dual-clock expiry (wall-clock UTC and monotonic nanoseconds). A background cleanup runner periodically sweeps for expired grants, revokes the underlying OS privilege, and garbage-collects completed tombstone records after a configurable retention window.

The helper has no network code path. All communication is local IPC; signature authority is external to this binary.

### Platform Support

| Platform | Grant Mechanism | Clock Source | Status |
|---|---|---|---|
| Linux | `/etc/sudoers.d/thand-<request_id>` drop-in file with `visudo -cf` validation | `CLOCK_BOOTTIME` (suspend-inclusive) | ✅ Complete |
| macOS | `dseditgroup` admin group membership via Directory Services | `CLOCK_MONOTONIC` | ✅ Complete |
| Windows | PowerShell `Add-LocalGroupMember` / `Remove-LocalGroupMember` cmdlets | `GetTickCount64` | ✅ Complete |

### Core Components

- **`main.go`** — Entry point. Loads configuration from environment variables, constructs platform-specific dependencies via `buildPlatformDependencies()` (runtime dispatch on `GOOS`), builds the cryptographic verifier with embedded trusted keys, creates the file-based state store, and starts the IPC server and cleanup runner concurrently. Handles graceful shutdown on `SIGINT`/`SIGTERM` with a 250 ms drain window.
- **`server.go`** — IPC accept loop. Delegates each incoming connection to the handler for the full request lifecycle.
- **`cleanup.go`** — Background cleanup runner. Performs a blocking startup sweep then periodic sweeps at a configurable interval. For each persisted grant: revokes expired grants (unless the user was already privileged before the grant), marks them as completed tombstones, and purges tombstones older than the retention window.
- **`domain/`** — Shared protocol and domain types.
  - `types.go` — Protocol frame structs (`RequestFrame`, `ChallengeFrame`, `SignedResponseFrame`, `ResultFrame`), internal request/result types (`GrantRequest`, `RevokeRequest`, `GrantResult`), and the persisted `GrantState` struct.
  - `grant_state.go` — Grant lifecycle predicates: `IsCompletedGrantState()`, `IsActiveGrantState()`, `IsExpiredGrantState()` with fail-secure dual-clock expiry logic.
- **`handler/`** — Request routing, authentication, and action handling.
  - `interfaces.go` — Clean abstraction boundaries: `IPCServer`, `IPCConn`, `GrantEngine`, `SignatureVerifier`, `StateStore`, `Clock`. All dependencies are injected via interfaces for full testability.
  - `handler.go` — Per-connection router. Reads the request frame with timeout enforcement, dispatches to `handleGrant()` or `handleRevoke()`.
  - `auth.go` — Challenge-response authentication flow: nonce generation → challenge frame → signed response read → payload validation → Ed25519 signature verification against pinned keys.
  - `handle_grant.go` — Grant flow with idempotency detection (same `request_id` + matching params = success), conflict detection (same `request_id` + different params = `request_conflict`), active grant checks (same username with active grant = `active_grant_exists`), and best-effort rollback if state persistence fails after a successful OS-level grant.
  - `handle_revoke.go` — Revoke flow with baseline privilege tracking. If the user was already privileged before the grant (`WasAlreadyPrivileged`), the OS-level revoke is skipped. Already-completed grants return success (idempotent). State is marked completed with `CompletedAtWallUTC`.
  - `validation.go` — Username validation delegating to `identity.ValidAccountName()`.
  - `errors.go` — Client-facing error codes and internal error classification.
- **`verify/`** — Cryptographic signature verification.
  - `verifier.go` — `Verifier` type holding trusted Ed25519 public keys. Provides `GenerateNonce()` (32 random bytes, base64-encoded), `CanonicalPayload()` (deterministic JSON marshaling for signing), `DecodeSignedPayload()`, `DecodeSignature()`, `MatchSignedPayload()` (validates all fields against request + nonce), and `Verify()` (Ed25519 signature check).
  - `keys_embedded.go` — Compile-time key embedding via `go:embed` directive. Reads `*.pem` files from `verify/keys/` directory. Files ending in `.pem.example` are ignored.
  - `key_parse.go` — Parses trusted keys from both raw base64 and PEM (PKIX Ed25519) formats.
  - `keys/` — Directory for pinned public key PEM files. Key IDs are derived from filenames (minus `.pem` extension). No production keys are committed by default.
- **`grant/`** — Platform-specific privilege engines. All engines validate `request_id` and `username` inputs and treat revoke as idempotent.
  - `linux_engine.go` — Creates a sudoers drop-in file at `/etc/sudoers.d/thand-<request_id>` with `visudo -cf` validation before activation. Verifies the base sudoers file includes the target directory via `#includedir` or `@includedir`. File permissions set to `0440`. Revoke removes the file (idempotent on `ENOENT`).
  - `darwin_engine.go` — Manages admin group membership via `dseditgroup -o edit -a/-d` and verifies membership via `dsmemberutil checkmembership`. Revoke suppresses "not a member" errors for idempotency.
  - `windows_engine.go` — Manages local Administrators group membership via PowerShell `Get-LocalGroupMember`, `Add-LocalGroupMember`, `Remove-LocalGroupMember` cmdlets. Handles race conditions (if add fails but user is already a member, treats as success). Distinguishes local vs domain-qualified principals for membership checks.
  - All engines support a `WasAlreadyPrivileged` baseline check — if the user was already in the privileged group/sudoers before the grant, the flag is set and revoke is skipped.
- **`identity/`** — Account name validation.
  - `validation.go` — `ValidAccountName()` enforces pattern `^[A-Za-z_][A-Za-z0-9._-]*[$]?$` with a 32-character maximum. `ValidWindowsAdminGroup()` enforces pattern `^[A-Za-z][A-Za-z0-9 ._-]*$` with a 64-character maximum. Used by both config validation and request handling to prevent shell injection.
- **`ipc/`** — Unix domain socket transport.
  - `ipc.go` — `UnixServer` with newline-delimited JSON framing, 16 KB max frame size, and 250 ms read/write poll intervals (allows context cancellation). Creates socket directory with `0750` permissions. Removes stale sockets on startup (with safety check to avoid removing non-socket files).
  - `ipc_access_unix.go` — Socket file permissions (`0660`) and `chown` for configured user/group (Linux/macOS).
  - `ipc_access_windows.go` — Socket ACLs via `icacls` (SYSTEM:Full, socket_user:Modify).
- **`clock/`** — Per-OS monotonic clock implementations with wall-clock fallback.
  - `clock.go` — `NowWallUTC()` returns current UTC wall time. Platform-specific `NowMonoNS()` methods in build-tagged files.
  - `mono_linux.go` — `CLOCK_BOOTTIME` (suspend-inclusive monotonic).
  - `mono_macos.go` — `CLOCK_MONOTONIC`.
  - `mono_windows.go` — `GetTickCount64()` converted to nanoseconds.
  - All platforms fall back to process-relative time (`time.Since(started)`) if the platform-specific source fails.
- **`state/`** — Atomic state persistence.
  - `store.go` — `FileStore` using a mutex-protected single JSON file with schema version 1. Operations: `Put()` (upsert by `request_id`), `Delete()`, `List()`. Atomic writes via temp file → `fsync` → rename. State directory created with `0700` permissions.
  - `sync_dir_unix.go` — Calls `Sync()` on the directory file descriptor after rename for durability (Linux/macOS).
  - `sync_dir_windows.go` — No-op on Windows (atomic rename semantics are sufficient).
- **`tools/sign_request/`** — CLI utility to generate `request` + `signed_response` protocol frames from a private key. Supports both offline mode (provide `-nonce` manually) and socket mode (`-socket` for full automated challenge-response flow against a running daemon).
- **`tools/generate_test_key/`** — CLI utility to generate Ed25519 keypairs for testing. Outputs `<key-id>.pem` (public, `0644`) and `<key-id>.private.pem` (PKCS8 private, `0600`).
- **`tools/windows_unix_socket_smoke/`** — Minimal server/client pair for verifying Unix socket support on Windows with Go's `net` package.

## IPC Protocol

Communication uses **newline-delimited JSON** over a Unix domain socket. Each frame is a single JSON object terminated by `\n`. Maximum frame size is **16 KB**. A single connection handles one complete request lifecycle (request → challenge → signed_response → result), then closes.

### Frame Flow

```
Client                          Server
  │                                │
  │──── 1. Request Frame ────────▶│
  │                                │
  │◀──── 2. Challenge Frame ──────│
  │                                │
  │──── 3. Signed Response ──────▶│
  │                                │
  │◀──── 4. Result Frame ─────────│
  │                                │
```

### 1. Request Frame (client → server)

```json
{
  "type": "request",
  "action": "grant",
  "workflow_id": "wf-abc-123",
  "request_id": "req-xyz-456",
  "username": "alice",
  "duration_seconds": 3600
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | Must be `"request"` |
| `action` | string | yes | `"grant"` or `"revoke"` |
| `workflow_id` | string | yes | Workflow identifier for audit correlation |
| `request_id` | string | yes | Unique request identifier (used for idempotency and state lookup) |
| `username` | string | yes | Local account to elevate/revoke |
| `duration_seconds` | int64 | grant only | Grant duration in seconds (must be > 0 for grants) |

### 2. Challenge Frame (server → client)

```json
{
  "type": "challenge",
  "nonce": "base64-encoded-32-random-bytes"
}
```

The server generates a cryptographically random 32-byte nonce and sends it to the client. The client must include this nonce in the signed payload.

### 3. Signed Response Frame (client → server)

```json
{
  "type": "signed_response",
  "key_id": "thand-server-current",
  "signature": "<base64-ed25519-signature>",
  "signed_payload": "<base64-encoded-json>"
}
```

The `signed_payload` is a base64-encoded JSON object with the canonical `SignedPayload` schema:

```json
{
  "nonce": "<must match challenge nonce>",
  "action": "grant",
  "workflow_id": "wf-abc-123",
  "request_id": "req-xyz-456",
  "username": "alice",
  "duration_seconds": 3600
}
```

The `signature` is the Ed25519 detached signature over the deterministic JSON serialization of the `SignedPayload`, base64-encoded. The `key_id` identifies which pinned public key to use for verification.

### 4. Result Frame (server → client)

```json
{
  "type": "result",
  "status": "ok",
  "request_id": "req-xyz-456"
}
```

On error:

```json
{
  "type": "result",
  "status": "error",
  "error": "unauthorized",
  "request_id": "req-xyz-456"
}
```

## Authentication

Every request undergoes a challenge-response signature verification flow:

1. **Nonce generation** — The server generates 32 cryptographically random bytes (base64-encoded) and sends a `challenge` frame.
2. **Payload construction** — The client constructs a `SignedPayload` JSON object containing the nonce, action, workflow_id, request_id, username, and duration_seconds. All fields must exactly match the original request frame.
3. **Signing** — The client serializes the payload to canonical JSON and signs it with an Ed25519 private key whose corresponding public key is pinned in the helper binary.
4. **Verification** — The server decodes the signed payload, validates all fields match the original request and nonce, then verifies the Ed25519 signature against the trusted public key identified by `key_id`.

### Trusted Key Management

- Public keys are embedded at compile time from PEM files in `verify/keys/*.pem` via Go's `go:embed` directive.
- Key IDs are derived from filenames (e.g., `thand-server-current.pem` → key ID `thand-server-current`).
- Files ending in `.pem.example` are ignored.
- At least one trusted key must be present at build time; the verifier returns an error otherwise.
- Changing pinned keys requires rebuilding and restarting the helper.
- Keys can also be overridden programmatically via `WithTrustedKeys()` or `WithTrustedKeysBase64()` options (primarily for testing).

## Grant State Lifecycle

Each grant progresses through a defined lifecycle tracked in the persistent state file:

```
┌──────────┐     duration expires      ┌──────────┐     retention expires     ┌─────────┐
│  Active   │ ──────────────────────▶  │ Completed │ ───────────────────────▶  │ Purged  │
└──────────┘                           └──────────┘                            └─────────┘
      │                                      ▲
      │        explicit revoke               │
      └──────────────────────────────────────┘
```

### States

| State | Condition | Description |
|---|---|---|
| **Active** | `CompletedAtWallUTC` is zero AND not expired | Grant is live; OS privilege is in effect. Blocks new grants for the same username. |
| **Expired** | Dual-clock expiry check passes | Duration has elapsed. Cleanup runner will revoke the OS privilege and mark completed. |
| **Completed** | `CompletedAtWallUTC` is non-zero | Tombstone record. OS privilege has been revoked (or was already revoked). Retained for audit/idempotency. |
| **Purged** | Completed + retention window elapsed | Record deleted from state file by cleanup runner. |

### Dual-Clock Expiry

Expiry is checked against **both** wall-clock UTC and monotonic nanoseconds to guard against clock manipulation:

- **Wall-clock check:** `GrantedAtWallUTC + DurationSeconds < now UTC` → expired.
- **Monotonic check:** `NowMonoNS - GrantedAtMonoNS >= DurationSeconds * 1e9` → expired.
- If either clock indicates expiry, the grant is expired.
- If monotonic timestamps are invalid (e.g., helper restarted, counter reset), falls back to wall-clock only.
- **Fail-secure:** If `DurationSeconds ≤ 0`, `GrantedAtMonoNS ≤ 0`, `GrantedAtWallUTC` is zero, or `nowWallUTC` is zero, the grant is treated as expired.

### Persisted Grant State Schema

The state file (`state.json`) uses schema version 1:

```json
{
  "version": 1,
  "grants": [
    {
      "request_id": "req-xyz-456",
      "workflow_id": "wf-abc-123",
      "username": "alice",
      "granted_at_wall_utc": "2026-04-19T10:00:00Z",
      "granted_at_mono_ns": 1234567890000,
      "duration_seconds": 3600,
      "was_already_privileged": false,
      "completed_at_wall_utc": "2026-04-19T11:00:00Z"
    }
  ]
}
```

| Field | Description |
|---|---|
| `request_id` | Unique grant identifier |
| `workflow_id` | Workflow correlation ID |
| `username` | Local account that was elevated |
| `granted_at_wall_utc` | UTC wall-clock time when grant was issued |
| `granted_at_mono_ns` | Monotonic clock nanoseconds when grant was issued |
| `duration_seconds` | Requested grant duration |
| `was_already_privileged` | `true` if the user was already in the privileged group before the grant (revoke will be skipped) |
| `completed_at_wall_utc` | Set when the grant is revoked or expires; indicates tombstone state. Omitted (`""`) while active. |

### Idempotency

- **Same `request_id` + same parameters** (workflow_id, username, duration_seconds): Returns success without re-granting. Safe to retry.
- **Same `request_id` + different parameters**: Returns `request_conflict` error.
- **Different `request_id` + same username with active grant**: Returns `active_grant_exists` error.
- **Revoke of already-completed grant**: Returns success (idempotent).

### Baseline Privilege Tracking

When a grant is issued, the engine checks whether the user is already a member of the privileged group. If so, `was_already_privileged` is set to `true` and the revoke step is skipped (both on explicit revoke and cleanup expiry) to avoid revoking privileges that were granted externally.

## Error Codes

The `error` field in result frames uses these stable client-facing codes:

| Code | Description |
|---|---|
| `invalid_request` | Malformed frame, missing fields, invalid username, or protocol violation |
| `unauthorized` | Signature verification failed, unknown `key_id`, or payload mismatch |
| `internal_error` | Server-side failure (state I/O, grant engine error, etc.) |
| `request_conflict` | `request_id` already exists with different parameters |
| `active_grant_exists` | Username already has an active (non-expired, non-completed) grant |

## Identity Validation

All usernames and group names are validated before use in OS commands to prevent injection:

| Context | Pattern | Max Length | Examples |
|---|---|---|---|
| Local account / group name | `^[A-Za-z_][A-Za-z0-9._-]*[$]?$` | 32 | `alice`, `_svc-agent`, `backup$` |
| Windows admin group | `^[A-Za-z][A-Za-z0-9 ._-]*$` | 64 | `Administrators`, `Local Admins` |

Validation is enforced at multiple layers: configuration loading (`config.Validate()`), request handling (`handler/validation.go`), and within each grant engine.

## Configuration

All configuration is loaded from environment variables. Duration values use Go `time.ParseDuration` format (e.g., `30s`, `5m`, `24h`).

### All Platforms

| Variable | Default | Description |
|---|---|---|
| `THAND_ELEVATE_SOCKET_PATH` | `/var/run/thand/elevate.sock` (Unix) / `C:\ProgramData\Thand\elevate.sock` (Windows) | Helper IPC socket path |
| `THAND_ELEVATE_STATE_PATH` | `/var/lib/thand/elevate/state.json` (Unix) / `C:\ProgramData\Thand\elevate\state.json` (Windows) | Persisted grant state file path |
| `THAND_ELEVATE_CLEANUP_INTERVAL` | `1m` | How often the cleanup runner sweeps for expired grants |
| `THAND_ELEVATE_REQUEST_TIMEOUT` | `30s` | Per-connection request timeout (covers the full challenge-response flow) |
| `THAND_ELEVATE_STATE_RETENTION` | `24h` | How long completed grant tombstones are retained before purging |
| `THAND_ELEVATE_SOCKET_USER` | *(unset)* | Set socket owner by username (optional) |
| `THAND_ELEVATE_SOCKET_GROUP` | *(unset)* | Set socket group by name (optional) |
| `THAND_ELEVATE_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`/`warning`, `error` |

### Linux

| Variable | Default | Description |
|---|---|---|
| `THAND_ELEVATE_SUDOERS_DIR` | `/etc/sudoers.d` | Directory for grant sudoers drop-in files |
| `THAND_ELEVATE_SUDOERS_FILE` | `/etc/sudoers` | Base sudoers file (checked for `#includedir`/`@includedir` of the sudoers dir) |
| `THAND_ELEVATE_VISUDO_BIN` | `visudo` | Path or name of the `visudo` binary used for syntax validation |

### macOS

| Variable | Default | Description |
|---|---|---|
| `THAND_ELEVATE_ADMIN_GROUP` | `admin` | macOS admin group name to manage membership in |
| `THAND_ELEVATE_DSEDITGROUP_BIN` | `dseditgroup` | Path or name of the `dseditgroup` binary |
| `THAND_ELEVATE_DSMEMBERUTIL_BIN` | `dsmemberutil` | Path or name of the `dsmemberutil` binary |

### Windows

| Variable | Default | Description |
|---|---|---|
| `THAND_ELEVATE_WINDOWS_ADMIN_GROUP` | `Administrators` | Windows local admin group name to manage membership in |

### Validation Rules

- All duration values must be > 0.
- `THAND_ELEVATE_SOCKET_USER` and `THAND_ELEVATE_SOCKET_GROUP`, if set, must match the account name pattern (≤ 32 chars, `^[A-Za-z_][A-Za-z0-9._-]*[$]?$`).
- `THAND_ELEVATE_ADMIN_GROUP` (macOS) must be a valid account name.
- `THAND_ELEVATE_WINDOWS_ADMIN_GROUP` (Windows), if set, must match the Windows admin group pattern (≤ 64 chars).
- Linux requires `THAND_ELEVATE_SUDOERS_DIR`, `THAND_ELEVATE_SUDOERS_FILE`, and `THAND_ELEVATE_VISUDO_BIN` to be non-empty.
- macOS requires `THAND_ELEVATE_DSEDITGROUP_BIN` and `THAND_ELEVATE_DSMEMBERUTIL_BIN` to be non-empty.

## Testing

### Unit and race tests

```bash
cd cmd/elevate
go test ./...
go test -race ./...
```

All tests run on any platform — **no real OS commands are executed**. Every external dependency (file I/O, OS commands, clock, state store) is injected via functional options and replaced with stubs/mocks in tests. This includes:

- Grant engines: `addMember`/`removeMember`/`checkMembership` closures (macOS), `writeFile`/`validateFile` closures (Linux), `runCommand` closure (Windows).
- IPC server: `mkdirAll`, `lstat`, `remove`, `listenUnix`, `chmod`, `chown`, `lookupUser`, `lookupGroup` functions.
- Clock: `NowMonoNS()` and `NowWallUTC()` return controlled values.
- State store: In-memory stub with optional error injection.

### Build

```bash
cd cmd/elevate
go build -o bin/elevate ./
```

### Run with real system paths — Linux (root)

```bash
sudo mkdir -p /var/run/thand /var/lib/thand/elevate
sudo chown root:root /var/run/thand /var/lib/thand/elevate
sudo chmod 755 /var/run/thand /var/lib/thand/elevate
```

```bash
sudo env \
  THAND_ELEVATE_SOCKET_PATH=/var/run/thand/elevate.sock \
  THAND_ELEVATE_SOCKET_USER="thand-agent" \
  THAND_ELEVATE_SOCKET_GROUP="thand-agent" \
  THAND_ELEVATE_SUDOERS_DIR=/etc/sudoers.d \
  THAND_ELEVATE_SUDOERS_FILE=/etc/sudoers \
  THAND_ELEVATE_VISUDO_BIN=visudo \
  THAND_ELEVATE_STATE_PATH=/var/lib/thand/elevate/state.json \
  THAND_ELEVATE_CLEANUP_INTERVAL=1m \
  THAND_ELEVATE_STATE_RETENTION=24h \
  THAND_ELEVATE_REQUEST_TIMEOUT=15m \
  THAND_ELEVATE_LOG_LEVEL=debug \
  ./bin/elevate
```

### Run with real system paths — macOS (root)

```bash
sudo mkdir -p /var/run/thand /var/lib/thand/elevate
sudo chown root:wheel /var/run/thand /var/lib/thand/elevate
sudo chmod 755 /var/run/thand /var/lib/thand/elevate
```

```bash
sudo env \
  THAND_ELEVATE_SOCKET_PATH=/var/run/thand/elevate.sock \
  THAND_ELEVATE_SOCKET_GROUP=thand-agent \
  THAND_ELEVATE_ADMIN_GROUP=admin \
  THAND_ELEVATE_DSEDITGROUP_BIN=/usr/sbin/dseditgroup \
  THAND_ELEVATE_DSMEMBERUTIL_BIN=/usr/bin/dsmemberutil \
  THAND_ELEVATE_STATE_PATH=/var/lib/thand/elevate/state.json \
  THAND_ELEVATE_CLEANUP_INTERVAL=1m \
  THAND_ELEVATE_STATE_RETENTION=24h \
  THAND_ELEVATE_REQUEST_TIMEOUT=15m \
  THAND_ELEVATE_LOG_LEVEL=debug \
  ./bin/elevate
```

## Manual Protocol Smoke Test

### Setup: Generate test keypair and pin

```bash
KEYDIR="$(mktemp -d /tmp/elevate-keys-XXXXXX)"
cd cmd/elevate
go run ./tools/generate_test_key \
  -out-dir "$KEYDIR" \
  -key-id local-test-key
```

Copy the generated public key into pinned keys, rebuild, restart:

```bash
KEY_ID="local-test-key"
cp "$KEYDIR/${KEY_ID}.pem" "verify/keys/${KEY_ID}.pem"
go build -o bin/elevate ./
# restart your running elevate process
```

### Grant flow (manual via socat)

1. Open socket session (same connection for both frames):

```bash
socat - UNIX-CONNECT:/var/run/thand/elevate.sock
```

2. Send a request frame:

```json
{"type":"request","action":"grant","workflow_id":"wf-manual-1","request_id":"req-manual-1","username":"alice","duration_seconds":600}
```

3. Copy the `nonce` value from the challenge response.

4. Generate the signed response frame:

```bash
cd cmd/elevate
go run ./tools/sign_request \
  -private-key "$KEYDIR/${KEY_ID}.private.pem" \
  -key-id "$KEY_ID" \
  -nonce "<CHALLENGE_NONCE>" \
  -action grant \
  -workflow-id wf-manual-1 \
  -request-id req-manual-1 \
  -username alice \
  -duration-seconds 600
```

This outputs two lines:
- `request` JSON
- `signed_response` JSON

5. Paste the `signed_response` line into the open socket session.

Expected: `{"type":"result","status":"ok","request_id":"req-manual-1"}`

### Revoke flow (manual via socat)

1. Open a new socket session:

```bash
socat - UNIX-CONNECT:/var/run/thand/elevate.sock
```

2. Send a revoke request frame (same `request_id` as the grant):

```json
{"type":"request","action":"revoke","workflow_id":"wf-manual-1","request_id":"req-manual-1","username":"alice"}
```

3. Copy the `nonce` from the challenge response, then generate the signed response:

```bash
go run ./tools/sign_request \
  -private-key "$KEYDIR/${KEY_ID}.private.pem" \
  -key-id "$KEY_ID" \
  -nonce "<CHALLENGE_NONCE>" \
  -action revoke \
  -workflow-id wf-manual-1 \
  -request-id req-manual-1 \
  -username alice
```

4. Paste the `signed_response` line into the socket session.

Expected: `{"type":"result","status":"ok","request_id":"req-manual-1"}`

### Automated flow via socket mode

The `sign_request` tool supports a `-socket` flag that handles the full protocol flow automatically (connect → send request → read challenge → sign → send signed response → read result):

```bash
cd cmd/elevate
go run ./tools/sign_request \
  -socket /var/run/thand/elevate.sock \
  -private-key "$KEYDIR/${KEY_ID}.private.pem" \
  -key-id "$KEY_ID" \
  -action grant \
  -workflow-id wf-auto-1 \
  -request-id req-auto-1 \
  -username alice \
  -duration-seconds 600 \
  -timeout 10s
```

### Negative-path testing

- Use an unknown `key_id` or mismatched private key → `{"status":"error","error":"unauthorized"}`
- Send a duplicate `request_id` with different params → `{"status":"error","error":"request_conflict"}`
- Grant to a user who already has an active grant → `{"status":"error","error":"active_grant_exists"}`

## Notes

- **Go version:** Requires Go 1.25+. Single external dependency: `golang.org/x/sys v0.41.0`.
- **Trusted keys:** Pinned key IDs come from filenames in `verify/keys/*.pem`. No production keys are committed by default. You must add at least one `.pem` key file before building the daemon.
- **Graceful shutdown:** On `SIGINT` or `SIGTERM`, the helper cancels the context for both the IPC server and cleanup runner, with a 250 ms drain window before exit.
- **State file versioning:** The state file uses `"version": 1`. The store validates the schema version on load and rejects unknown versions.
- **Atomic writes:** State persistence uses temp file → `fsync` → rename → directory `fsync` (Unix) to survive power loss and crashes.
- **No network path:** The helper communicates exclusively over local IPC. Signature authority is external to this binary.
- **Idempotent operations:** Grant/revoke on all platforms is idempotent. Adding an existing member, removing a non-member, or removing a non-existent sudoers file is treated as success.
- **Best-effort rollback:** If the state store fails to persist a grant after the OS-level grant succeeds, the handler attempts to revoke the OS-level grant to prevent untracked elevation. Rollback failures are logged at error level.
- **Structured logging:** All log output uses `slog` with structured fields (`component`, `action`, `request_id`, `workflow_id`, `username`, etc.) for log aggregation.
- **Windows socket smoke test:** `tools/windows_unix_socket_smoke/` contains a minimal client/server pair for verifying Unix domain socket support on Windows with Go's `net` package.
