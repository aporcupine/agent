# `cmd/elevate`

Local privileged helper for temporary local-admin elevation.

## Overview

`elevate` is a standalone daemon intended to run as root (Linux, macOS).  
It accepts local IPC requests, verifies a challenge-response signature using pinned public keys, performs OS-level grant/revoke operations, and persists grant state for cleanup/recovery.

### Platform Support

| Platform | Grant Mechanism | Clock Source | Status |
|---|---|---|---|
| Linux | `/etc/sudoers.d/thand-<request_id>` with `visudo` validation | `ClockGettime(CLOCK_BOOTTIME)` | ✅ Complete |
| macOS | `dseditgroup` admin group membership via Directory Services | `ClockGettime(CLOCK_MONOTONIC)` | ✅ Complete |
| Windows | `NetLocalGroupAddMembers` / PowerShell fallback | — | ⚠️ Not started |

### Core Components

- `main.go`
  - Loads config from env.
  - Builds platform-specific dependencies (Linux or macOS) via `buildPlatformDependencies()`.
  - Starts server + cleanup runner.
- `ipc/`
  - Unix socket transport (all platforms).
  - Newline-delimited JSON framing.
  - Socket permissions + optional socket group ownership (`THAND_ELEVATE_SOCKET_GID`).
- `handler/`
  - Request router (`grant`/`revoke`).
  - Challenge/response signature verification flow.
  - Sanitized error responses and structured `slog` logging.
- `verify/`
  - Nonce handling + signed payload validation.
  - Ed25519 verification against compile-time pinned keys (`verify/keys/*.pem`).
- `grant/`
  - **Linux:** `linux_engine.go` — sudoers.d drop-in file management with `visudo -cf` validation.
  - **macOS:** `darwin_engine.go` — admin group membership via `dseditgroup`/`dsmemberutil`.
  - Both engines share validation helpers (`isValidRequestID`, `isValidUsername`).
  - Revoke is idempotent on both platforms.
- `clock/`
  - `unix_clock.go` — unified monotonic + wall-clock implementation using `ClockGettime`.
  - `clock_source_linux.go` — selects `CLOCK_BOOTTIME` (survives suspend).
  - `clock_source_darwin.go` — selects `CLOCK_MONOTONIC`.
  - Falls back to process-relative time on syscall error.
- `state/`
  - Atomic state persistence (`tmp + fsync + rename + dir fsync`).
  - Single versioned JSON file with dual-clock expiry (monotonic + wall-clock fallback).
- `cleanup.go`
  - Startup and periodic sweep of expired grants.
  - Revokes expired entries and removes state records.
- `tools/sign_request/`
  - Local test utility to generate `request` + `signed_response` frames from a private key.
- `tools/generate_test_key/`
  - Local test utility to generate Ed25519 keypairs for testing.

## Configuration

Environment variables (all platforms):

| Variable | Default | Description |
|---|---|---|
| `THAND_ELEVATE_SOCKET_PATH` | `/var/run/thand/elevate.sock` | Unix socket path for IPC |
| `THAND_ELEVATE_SOCKET_GID` | `-1` (disabled) | GID for socket directory/file ownership |
| `THAND_ELEVATE_STATE_PATH` | `/var/lib/thand/elevate/state.json` | State file for grant persistence |
| `THAND_ELEVATE_CLEANUP_INTERVAL` | `1m` | How often to sweep for expired grants |
| `THAND_ELEVATE_REQUEST_TIMEOUT` | `30s` | Timeout for a single IPC request lifecycle |
| `THAND_ELEVATE_LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

Linux-specific:

| Variable | Default | Description |
|---|---|---|
| `THAND_ELEVATE_SUDOERS_DIR` | `/etc/sudoers.d` | Directory for temporary sudoers drop-in files |
| `THAND_ELEVATE_SUDOERS_FILE` | `/etc/sudoers` | Main sudoers file (checked for `#includedir`) |
| `THAND_ELEVATE_VISUDO_BIN` | `visudo` | Path to visudo binary for syntax validation |

macOS-specific:

| Variable | Default | Description |
|---|---|---|
| `THAND_ELEVATE_ADMIN_GROUP` | `admin` | macOS admin group name |
| `THAND_ELEVATE_DSEDITGROUP_BIN` | `dseditgroup` | Path to dseditgroup binary |
| `THAND_ELEVATE_DSMEMBERUTIL_BIN` | `dsmemberutil` | Path to dsmemberutil binary |

## Testing

### Unit and race tests

```bash
cd cmd/elevate
go test ./...
go test -race ./...
```

All tests use mock/dummy data and run on any platform — no real OS commands are executed.

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
  THAND_ELEVATE_SOCKET_GID="$(id -g thand-agent)" \
  THAND_ELEVATE_SUDOERS_DIR=/etc/sudoers.d \
  THAND_ELEVATE_SUDOERS_FILE=/etc/sudoers \
  THAND_ELEVATE_VISUDO_BIN=visudo \
  THAND_ELEVATE_STATE_PATH=/var/lib/thand/elevate/state.json \
  THAND_ELEVATE_CLEANUP_INTERVAL=1m \
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
  THAND_ELEVATE_SOCKET_GID="$(dscl . -read /Groups/thand-agent PrimaryGroupID | awk '{print $2}')" \
  THAND_ELEVATE_ADMIN_GROUP=admin \
  THAND_ELEVATE_DSEDITGROUP_BIN=/usr/sbin/dseditgroup \
  THAND_ELEVATE_DSMEMBERUTIL_BIN=/usr/bin/dsmemberutil \
  THAND_ELEVATE_STATE_PATH=/var/lib/thand/elevate/state.json \
  THAND_ELEVATE_CLEANUP_INTERVAL=1m \
  THAND_ELEVATE_REQUEST_TIMEOUT=15m \
  THAND_ELEVATE_LOG_LEVEL=debug \
  ./bin/elevate
```

## Manual Protocol Smoke Test

1. Open socket session (same connection for both frames):

```bash
socat - UNIX-CONNECT:/var/run/thand/elevate.sock
```

2. Send a request frame:

```json
{"type":"request","action":"grant","workflow_id":"wf-manual-1","request_id":"req-manual-1","username":"alice","duration_seconds":600}
```

3. Copy nonce from challenge response.

4. (Success path) Generate a local test keypair and pin the public key:

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

5. Generate frames with signer tool using matching private key + key id:

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

Paste the `signed_response` line into the open socket session as the second frame.

Expected:
- success: `{"type":"result","status":"ok",...}`

Negative-path tip:
- Use an unknown `key_id` or mismatched private key to get `{"status":"error","error":"unauthorized"}`.

## Notes

- Pinned key IDs come from filenames in `cmd/elevate/verify/keys/*.pem`.
- No production keys are committed by default. You must add at least one `.pem` key file before starting the daemon without override options.
- Changing pinned keys requires rebuilding/restarting the helper.
- Helper has no network code path; signature authority is external to this binary.
- macOS grant/revoke via `dseditgroup` is idempotent — adding an existing member or removing a non-member is safe.
- Linux grant/revoke via sudoers.d is idempotent — removing a non-existent file is treated as success.
