# Local Admin — Temporary Elevation

## Why

We are expanding on the existing feature set to allow temporary admin elevation to either the last active user on the device OR a nominated user through the execution policy in thand within the below operating systems. The temporary elevation will have a default of 60 minutes, but can be specified to be longer/shorter as needed through the thand configuration.

*MacOS
    *MacOS 15.7.4
    *MacOS 26.3

*Windows
    *Windows 11

*Linux 
    *Debian
    *Ubuntu
    *Arch Linux
    *Fedora
    *Red Hat Enterprise Linux (RHEL)
    *openSUSE
    *Gentoo
    *Slackware
    *NixOS

## What

We will know this is accomplished because we will be able to temporarily elevate users across the nominated operating systems under "Why" above, with the configuration specified for the provider.

We also need to do this in the most secure method possible, to ensure that we are not opening root access to the thand-agent entirely.

### What of Linux

- Overview: Temporary, auditable sudo elevation via a small root-owned daemon that verifies agent-signed challenges before writing time-limited files to /etc/sudoers.d. It is invoked by the `thand-agent` over a Unix domain socket as part of the agent's elevation workflow.

- Implementation status: **✅ Helper-side complete.** The elevation helper (`cmd/elevate/`) is implemented with sudoers.d grant/revoke, challenge-response authentication, state persistence, and cleanup. The agent-side provider (`internal/providers/local-admin/`) is not yet implemented.

- Risks & Mitigations:
    - Root compromise: daemon runs as root — minimize code, audit regularly, and limit functionality. The helper has zero network access and is a separate Go module with minimal dependencies.
    - Replay/signature misuse: include nonce + request_id; enforce one-time use via server-side consumption tracking. No timestamps are used in the verification flow.
    - Stale sudoers after crash/reboot: dual-clock expiry strategy (monotonic primary, wall-clock fallback after reboot). Cleanup runs at startup and periodically (configurable, default 1m).
    - Key compromise: private signing key resides on the thand server — the helper has the server's public key pinned at build time via embedded PEM files. Key rotation supported via `key_id`.
    - This application supports revocation through the Unix socket.

### What of macOS

- Overview: Temporary, auditable admin elevation via a small root-owned daemon that verifies agent-signed challenges before adding/removing users from the `admin` group using Directory Services (`dseditgroup`). It is invoked by the `thand-agent` over a Unix domain socket as part of the agent's elevation workflow.

- Implementation status: **⚠️ Not started.** Requires `grant/darwin_engine.go` and `clock/darwin_clock.go` in the helper.

- Risks & Mitigations:
    - Root compromise: daemon runs as root — minimize code, audit regularly, and limit functionality.
    - Replay/signature misuse: same challenge-response protocol as Linux — nonce + request_id, server-side consumption tracking.
    - Stale group membership after crash/reboot: same single versioned JSON state file and dual-clock expiry strategy as Linux. On startup and periodically, scan state to revoke expired grants via `dseditgroup`; treat already-removed membership as success and log results.
    - Key compromise: same embedded public key approach as Linux with key rotation via `key_id`.
    - This application supports revocation through the Unix socket.


### What of Windows

- Overview: Temporary, auditable elevation via a small Windows Service running as `LocalSystem` that verifies `thand-agent` signed challenges over a **Unix domain socket** (supported natively since Windows 10 1803) and then adds/removes local `Administrators` membership. Persist grant state in the same single versioned JSON format as Linux/macOS.

- Implementation status: **⚠️ Not started.** Requires `grant/windows_engine.go` and `clock/windows_clock.go` in the helper.

- Implementation notes (concise):
    - APIs: use Win32 NetAPI (`NetLocalGroupAddMembers` / `NetLocalGroupDelMembers`, `NetUserAdd` / `NetUserDel`) or equivalent PowerShell cmdlets for prototypes (`Add-LocalGroupMember` / `Remove-LocalGroupMember`).
    - IPC: **Unix domain socket** — same transport and code path as Linux/macOS. Windows has supported Unix domain sockets natively since Windows 10 version 1803 / Windows Server 2019. No named pipes or platform-specific IPC code needed.
    - Persistence & cleanup: same single versioned JSON state file with dual-clock expiry as Linux/macOS; scan on startup and periodically to revoke expired grants idempotently and log outcomes.

- Risks & mitigations (brief):
    - SYSTEM compromise: service runs as `LocalSystem` — keep code small, signed, and enforce socket file ACLs + signature verification.
    - Policy reversion: detect AD/Intune/GPO managed devices and prefer central directory-managed elevation when enforced.


## Context

**Relevant files:**
- `internal/providers` — This is where the new local admin provider will be created. This folder and all subfolders/files are used for context to understand how the current providers work. This is also the folder that the new feature will be built into.
- `cmd/elevate/` — **Implemented.** The elevation helper daemon, built as a separate Go module. Contains all helper-side logic: IPC server, challenge-response auth, grant engines, state persistence, cleanup, signature verification.

**Architecture document:**
- `copilot/local-admin-architecture.md` — Full architecture document covering system context, component design, IPC protocol, per-OS mechanics, state persistence, security model, configuration, and workflow integration.

**Patterns to follow:**
 
- `/models/temporal.go` — This is how temporal is invoked, make sure that the new provider invokes this as the other providers do. Make sure the code is written into here as well.

**Key decisions already made:**
- This *MUST* work with temporal, the thand-agent does NOT have to be deployed on the user desktops for the current functionality but this WILL be required to be installed for the local-admin feature to work. This IS a requirement.
- **IPC transport:** Unix domain sockets on **all platforms** (Linux, macOS, Windows). Windows has supported Unix domain sockets natively since Windows 10 1803, so no named pipe or platform-specific IPC code is needed.
- **Elevation helper:** Separate Go module (`cmd/elevate/go.mod`), separate binary, runs as root/SYSTEM. The agent is an untrusted relay — it never runs as root.
- **State persistence:** Single versioned JSON file (not one-per-grant) with dual-clock expiry (monotonic primary, wall-clock fallback after reboot).
- **Signing trust model:** Thand server is sole authority. Helper has server's public key pinned via embedded PEM files at build time. Agent relays nonce challenges to server for signing. No local signing keys.

## Constraints

**Must:**
- Providers go into internal/providers
- Elevation helper in cmd/elevate/
- Use Go libraries to interact with each operating system
- Unix domain sockets for IPC on all platforms

**Must not:**
- No new dependencies unless they provide significant reduction in code, are more reliable and/or reduce security risk
- Don't modify unrelated code
- Don't refactor existing code
- No named pipes or platform-specific IPC transport

**Out of scope:**
- Windows cannot interact with Local Active Directory or Hybrid Active Directory
- Anything outside the minimal versions specified under ##Why

## Tasks

Break into tasks that:
- Come up with an architecture document which shows how this is going to be architected, and we will review this document before sending it to create the code
- Can each be completed in separate steps, e.g a step for Linux, macOS and Windows
- Have a clear verification/testing on each step with local tests
- Are safe to commit independently, e.g there are no conflicts on the PRs

### Progress

| Task | Description | Status |
|---|---|---|
| Architecture document | `copilot/local-admin-architecture.md` | ✅ Complete |
| T2: Elevation helper core + IPC server | `cmd/elevate/` — sub-package architecture with config, domain types, handler, IPC, state, verify, clock, tools | ✅ Complete (Linux) |
| T3: Linux grant/revoke (helper-side) | `cmd/elevate/grant/linux_engine.go` — sudoers.d management with visudo validation | ✅ Complete |
| T1: Agent-side provider scaffold | `internal/providers/local-admin/` — provider registration, IPC client, AuthorizeRole/RevokeRole | ⚠️ Not started |
| T4: macOS grant/revoke | `cmd/elevate/grant/darwin_engine.go` + `clock/darwin_clock.go` | ⚠️ Not started |
| T5: Windows grant/revoke | `cmd/elevate/grant/windows_engine.go` + `clock/windows_clock.go` | ⚠️ Not started |
| T6: Example configs + documentation | Provider/role examples, docs | ⚠️ Not started |

## Done

- ✅ Architecture document created and reviewed
- ✅ Elevation helper daemon implemented for Linux (`cmd/elevate/`)
  - Sub-package architecture: `clock/`, `config/`, `domain/`, `grant/`, `handler/`, `ipc/`, `state/`, `verify/`, `tools/`
  - Hub-and-spoke interface pattern via `handler/interfaces.go`
  - Separate Go module (`cmd/elevate/go.mod`)
  - Environment-variable-driven configuration (`THAND_ELEVATE_*`)
  - Ed25519 signature verification with embedded trusted keys
  - Single versioned JSON state file with atomic writes
  - Dual-clock expiry strategy (monotonic + wall-clock fallback)
  - Challenge-response authentication (nonce-based, no timestamps)
  - Linux grant engine: sudoers.d drop-in files with visudo validation
  - Testing tools: keypair generation, signed frame production
- ✅ Decision: Unix domain sockets for all platforms (no named pipes)