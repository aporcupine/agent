# PR Review: `feat/macos-elevate-merge` → `main`

**Reviewer:** Code Review  
**Date:** 2026-04-19  
**Scope:** All files in `cmd/elevate/` plus root `.gitignore`

This module is entirely new on this branch. Every finding below is a new issue introduced by this PR.

---

## High

### H1 — `darwin_engine.Grant` calls `addMember` even when user is already in the admin group; `dseditgroup` returns an error for duplicate membership

**File:** `cmd/elevate/grant/darwin_engine.go`  
**Lines:** 157–167

```go
alreadyPrivileged, err := e.checkAlreadyPrivileged(ctx, req.Username)
...
if err := e.addMember(ctx, req.Username, e.adminGroup); err != nil {
    return domain.GrantResult{}, fmt.Errorf("add to admin group: %w", err)
}
```

The `checkAlreadyPrivileged` hook is a stub that always returns `false` (`darwin_engine.go` lines 79–84). There is no early-return when `alreadyPrivileged=true`, unlike the Linux engine (`linux_engine.go` lines 150–158) which short-circuits and skips writing the sudoers file.

On macOS, `dseditgroup -o edit -a <user> -t user <group>` **returns a non-zero exit code with an error** if the user is already a member of the group. The `addMember` closure does not suppress this error (contrast with `removeMember` which suppresses `"not a member"`). Therefore:

- If a user is already in the admin group via any out-of-band mechanism (manually added, another tool), a grant request via `elevate` will fail with an opaque `dseditgroup add failed` error rather than succeeding idempotently.
- The `WasAlreadyPrivileged` field will never reflect the true OS state because the stub returns `false` and the call fails before `GrantResult` is returned.

**Recommendation:** Either (a) handle the `"already a member"` error string from `dseditgroup` in `addMember` and treat it as success (similar to the `"not a member"` handling in `removeMember`), or (b) follow the Linux pattern: if `checkAlreadyPrivileged` returns `true`, skip `addMember` and return early. The real hook implementation (state layer) should be wired to a `dsmemberutil` check before the sudoers/group-add path.

---

### H2 — `darwin_engine.Revoke` does not validate the username; inconsistent with Windows

**File:** `cmd/elevate/grant/darwin_engine.go`  
**Lines:** 186–195

```go
func (e *DarwinEngine) Revoke(ctx context.Context, req domain.RevokeRequest) error {
    if !isValidRequestID(req.RequestID) {
        return ErrInvalidRevokeRequest
    }
    if err := e.removeMember(ctx, req.Username, e.adminGroup); err != nil {
```

The Windows engine (`windows_engine.go` line 155) validates both `RequestID` and `Username`:

```go
if !isValidRequestID(req.RequestID) || !isValidWindowsUsername(req.Username) {
    return ErrInvalidRevokeRequest
}
```

The Darwin engine validates only `RequestID`. An empty or malformed username is passed directly to `dseditgroup -o edit -d <username>`. While the handler (`handle_revoke.go` line 16) calls `validateRequestUsername` before reaching the engine, this relies entirely on the handler layer for input sanitisation. Any future caller of `DarwinEngine.Revoke` directly (e.g. from the cleanup runner) bypasses this check.

The cleanup runner (`cleanup.go` line 74) calls `grants.Revoke` directly with data from the state store. The state store accepts the username written by the grant handler which is validated; however, if state data is corrupted or migrated, an unvalidated username could reach `dseditgroup`.

**Recommendation:** Add `!isValidUsername(req.Username)` to the Revoke guard, consistent with the Windows engine.

---

### H3 — ~~Global `*.pem` gitignore silently hides production trust-anchor key files~~ ✅ Fixed

Replaced global `*.pem` with `cmd/elevate/verify/keys/*.pem` in `.gitignore`.

---

### H4 — No rollback if `stateStore.Put` fails after `engine.Grant` succeeds

**File:** `cmd/elevate/handler/handle_grant.go`  
**Lines:** 33–55

```go
result, err := h.grantEngine.Grant(ctx, ...)
...
if err := h.stateStore.Put(ctx, state); err != nil {
    return h.writeRequestError(ctx, conn, req, wrapInternal("persist grant state", err))
}
```

If `Grant` succeeds (user added to admin group on macOS) but `stateStore.Put` fails (disk full, I/O error), the user is in the admin group with no corresponding state record. The cleanup runner will never see this grant and will never revoke it. The client receives an error response and may retry with a new request ID, creating a second grant attempt. The original untracked elevation persists indefinitely.

This architectural gap exists across all platforms but is introduced new here for macOS. It should be called out for Darwin because the mechanism (group membership) is harder to audit out-of-band than a sudoers file.

**Recommendation:** On `stateStore.Put` failure, attempt `engine.Revoke` as a best-effort rollback before returning the error to the client. Log any rollback failure at error level.

---

## Medium

### M1 — `dseditgroup` error-string matching for "not a member" is brittle

**File:** `cmd/elevate/grant/darwin_engine.go`  
**Lines:** 119–127

```go
if strings.Contains(trimmed, "not a member") || strings.Contains(trimmed, "NotFound") {
    return nil
}
```

The idempotent-remove logic relies on substring matching against `dseditgroup` stderr output. The actual error text varies by macOS version and locale. On macOS 13+ the relevant error is typically `"eDSRecordNotFound"` embedded in a longer message; on older versions the text may differ. The string `"not a member"` does not appear verbatim in `dseditgroup` output; the tool reports `"Record was not updated"` or Directory Services error codes. If the strings don't match, Revoke returns an error for a non-member removal, breaking idempotency.

No test in `darwin_engine_test.go` exercises the actual dseditgroup error text path (the tests override `removeMember` entirely).

**Recommendation:** Parse the exit code or use `dsmemberutil checkmembership` before calling `dseditgroup -d`, making remove idempotent without relying on error text. Alternatively, document the exact macOS error strings verified against each macOS release and add regression tests.

---

### M2 — `config.validateForOS("darwin")` has only rejection tests; no positive acceptance test

**File:** `cmd/elevate/config/config_test.go`

There are two darwin-specific tests:
- `TestValidateForDarwinRequiresAdminGroup` (line 388) — rejects empty admin group
- `TestValidateForDarwinRequiresDirectoryServiceBinaries` (line 405) — rejects empty binary paths

Neither test verifies that a fully valid darwin config is accepted (`validateForOS("darwin")` returns `nil`). The second test does not separately cover the case where only `DseditgroupBin` is missing while `DsmemberutilBin` is present, or vice versa.

Contrast with the Windows test `TestValidateForWindowsDoesNotRequireLinuxSudoersFields` (line 320) which also tests the happy path.

**Recommendation:** Add:
1. A positive test: `TestValidateForDarwinAcceptsValidConfig` that calls `validateForOS("darwin")` on a fully populated config and expects `nil`.
2. Two separate rejection tests: one with only `DseditgroupBin` empty, one with only `DsmemberutilBin` empty.

---

### M3 — darwin `Grant` tests do not cover `checkAlreadyPrivileged` error path

**File:** `cmd/elevate/grant/darwin_engine_test.go`

`TestDarwinBaselinePrivilegeHook` tests the `true` return from the hook. There is no test for the error return path from `checkAlreadyPrivileged`. The code:

```go
alreadyPrivileged, err := e.checkAlreadyPrivileged(ctx, req.Username)
if err != nil {
    return domain.GrantResult{}, fmt.Errorf("check baseline privilege: %w", err)
}
```

is exercised only in the success cases. An error should cause `Grant` to return an error without calling `addMember`; this is untested.

**Recommendation:** Add a test using `WithDarwinCheckAlreadyPrivileged` that returns an error, asserting that `Grant` fails and `addMember` is not called.

---

### M4 — darwin `Grant` test for `WasAlreadyPrivileged=true` doesn't verify `addMember` is skipped

**File:** `cmd/elevate/grant/darwin_engine_test.go`, `TestDarwinBaselinePrivilegeHook`

The test checks that `res.WasAlreadyPrivileged == true` but the test's `addMember` stub unconditionally adds the user to the map. This masks H1: the test passes even though `addMember` is still called when `WasAlreadyPrivileged=true`. A proper test should assert that `addMember` was NOT called when the user was already privileged (once the early-return fix from H1 is in place).

---

### M5 — Goroutine leak in `run()` when either goroutine returns an error

**File:** `cmd/elevate/main.go`  
**Lines:** 218–246

```go
select {
case err := <-serverErr:
    return err          // cleanupErr goroutine leaked
case err := <-cleanupErr:
    return err          // serverErr goroutine leaked
case <-ctx.Done():
    // only waits for ONE of the two before timing out
```

When `serverErr` fires with an error, `run()` returns immediately. The `cleanupErr` goroutine continues to run with no context cancellation signal (the context is not cancelled by `run()` returning; it is cancelled by the signal handler). In the normal shutdown path (`ctx.Done()`), the inner select reads at most one of `serverErr` or `cleanupErr` before the 250 ms deadline, potentially leaving the other goroutine running after `main()` returns.

This is low-stakes for a single-process daemon that exits on error, but the pattern is incorrect and could cause resource leaks (open file descriptors, state store locks) if the process lingers.

**Recommendation:** Use `errgroup.Group` or cancel the context explicitly when either goroutine exits:

```go
ctx, cancel := context.WithCancel(ctx)
defer cancel()
// ... start goroutines; cancel on first return
```

---

### M6 — `server.go` silently discards per-connection `HandleConnection` errors

**File:** `cmd/elevate/server.go`  
**Lines:** 46–50

```go
if err := s.handler.HandleConnection(ctx, conn); err != nil {
    _ = conn.Close()
    // Chunk 1: no logging/error policy yet.
    continue
}
```

Connection-level errors (frame decode failures, IPC write errors, context timeouts) are silently dropped. For a security-sensitive privileged daemon, silent failure means failed grant/revoke attempts produce no audit trail. The comment "no logging/error policy yet" suggests this is acknowledged but deferred.

**Recommendation:** At minimum log connection errors at `Warn` level with the remote address and the error. This is especially important on macOS where `dseditgroup` call failures would be swallowed here if they propagate back up.

---

## Low

### L1 — macOS username validation rejects valid macOS usernames with uppercase characters

**File:** `cmd/elevate/grant/linux_engine.go`  
**Lines:** 28, 225–226 (shared with darwin via package-level `isValidUsername`)

```go
usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)
```

This pattern allows only lowercase usernames. On macOS, local account names are case-insensitive but the Directory Services record name can be mixed-case (e.g., `JDoe` created by an MDM). A valid macOS account name matching `^[A-Za-z_][A-Za-z0-9._-]*[$]?$` (the `identity.ValidAccountName` pattern) would be rejected.

The handler calls `validateRequestUsername` (which uses `identity.ValidAccountName` via `handler/validation.go`) and then the engine calls `isValidUsername` (the lowercase-only pattern from `linux_engine.go`). These two patterns are inconsistent. A username accepted by the handler could be rejected by the Darwin engine.

**Recommendation:** The Darwin engine should use `identity.ValidAccountName` (the same check used for the admin group and in the handler), not the Linux-specific `isValidUsername`. The linux pattern was designed for Linux POSIX usernames which are conventionally lowercase.

---

### L2 — No darwin-specific default state/socket paths

**File:** `cmd/elevate/config/config.go`  
**Lines:** 200–214

The `defaultStatePath()` function returns `/var/lib/thand/elevate/state.json` for all non-Windows platforms. On macOS, `/var/lib` is not a standard directory (it exists but is not FHS-standard or used by system daemons). macOS system daemons typically use `/var/db/` for persistent state. Similarly, while `/var/run` is acceptable for sockets, macOS launchd daemons typically use `/Library/Application Support/` or `/private/var/` paths.

This does not prevent operation but may confuse macOS administrators expecting macOS conventions.

**Recommendation:** Add a `darwin` case in `defaultStatePath()` and `defaultSocketPath()` returning macOS-idiomatic paths (e.g., `/private/var/db/thand/elevate/state.json`).

---

### L3 — `darwin_engine_test.go` does not test negative `DurationSeconds`

**File:** `cmd/elevate/grant/darwin_engine_test.go`  
**Lines:** 98–104

`TestDarwinGrantInvalidRequest` includes `DurationSeconds: 0` but not `DurationSeconds: -1`. While the `<= 0` check covers both, the negative case is worth including as a separate table entry to document intent and protect against future refactoring to `< 0`.

---

### L4 — `NewDarwinEngine` applies options before setting default implementations, creating inconsistency

**File:** `cmd/elevate/grant/darwin_engine.go`  
**Lines:** 87–100

```go
for _, opt := range opts {
    opt(e)           // opts applied here
}
if e.adminGroup == "" { ... }  // validation here
if e.addMember == nil {        // defaults set here, AFTER opts
    e.addMember = ...
}
```

Options are applied first, then validation is checked, then defaults are set. This means if a caller uses `WithAddMember(nil)` (explicitly setting to nil) to "undo" a previously applied option, the nil check `if e.addMember == nil` will install the default—which may not be the intended behaviour. The pattern is also inconsistent with how the `checkAlreadyPrivileged` default is set inside the initial struct literal (lines 79–84) before options are applied, making it overridable by options as expected.

This is a minor API robustness issue rather than a security concern.

---

### L5 — `admin_group` startup value not logged; harder to debug misconfiguration on macOS

**File:** `cmd/elevate/main.go`  
**Lines:** 36–47

The startup log includes `socket_path`, `state_path`, `cleanup_interval`, `request_timeout`, `socket_user`, `socket_group`, and `log_level` but not the macOS-specific `admin_group`, `dseditgroup_bin`, or `dsmemberutil_bin`. On Linux, the sudoers directory and file are also omitted.

For a security audit or incident response, knowing which admin group the daemon is managing is important. These are not sensitive values (they are configuration, not secrets).

**Recommendation:** Add `admin_group` (darwin), `dseditgroup_bin`, `dsmemberutil_bin` to the startup log conditionally (or always, since they are empty on non-macOS).

---

### L6 — `manual-test-key.pem` is untracked and will be silently hidden by the global `*.pem` ignore

**File:** `cmd/elevate/verify/keys/manual-test-key.pem` (untracked, listed in `git status`)

This file currently appears as `??` in `git status`. After the global `*.pem` rule is merged to main, it will no longer appear in `git status` at all. Since the file is a public key used with the test signing tool, it is not a private key secret, but its silent disappearance from `git status` could cause confusion.

The `.pem.example` convention already used (`my-key-example.pem.example`) is the right approach for documenting key format without committing key material. The `manual-test-key.pem` should either be committed (it is a public key only, contains no secret), added to a specific ignore path, or removed and replaced with a `.pem.example`.

---

## Summary Table

| ID  | Severity | File(s)                                            | Short Description                                                    |
|-----|----------|----------------------------------------------------|----------------------------------------------------------------------|
| H1  | High     | `grant/darwin_engine.go`                           | `addMember` called even if already privileged; no idempotent-add     |
| H2  | High     | `grant/darwin_engine.go`                           | `Revoke` does not validate username (unlike Windows engine)          |
| H3  | High     | `.gitignore`                                       | Global `*.pem` hides production trust-anchor key files from git      |
| H4  | High     | `handler/handle_grant.go`                          | No rollback if `stateStore.Put` fails after `engine.Grant` succeeds  |
| M1  | Medium   | `grant/darwin_engine.go`                           | `dseditgroup` error string matching for "not a member" is brittle    |
| M2  | Medium   | `config/config_test.go`                            | No positive acceptance test for valid darwin config                  |
| M3  | Medium   | `grant/darwin_engine_test.go`                      | `checkAlreadyPrivileged` error path untested                         |
| M4  | Medium   | `grant/darwin_engine_test.go`                      | Baseline privilege test doesn't assert `addMember` is skipped        |
| M5  | Medium   | `main.go`                                          | Goroutine leak in `run()` when server or cleanup goroutine errors    |
| M6  | Medium   | `server.go`                                        | Per-connection `HandleConnection` errors silently discarded          |
| L1  | Low      | `grant/linux_engine.go` (shared pattern)           | Lowercase-only username pattern rejects valid macOS mixed-case names |
| L2  | Low      | `config/config.go`                                 | No darwin-specific default state/socket paths                        |
| L3  | Low      | `grant/darwin_engine_test.go`                      | Negative `DurationSeconds` not in invalid-request table              |
| L4  | Low      | `grant/darwin_engine.go`                           | Option application order inconsistency vs default-setting            |
| L5  | Low      | `main.go`                                          | macOS-specific config fields absent from startup log                 |
| L6  | Low      | `verify/keys/manual-test-key.pem`                  | Untracked public key will be silently hidden by global `*.pem` rule  |
