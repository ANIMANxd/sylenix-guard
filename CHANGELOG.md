# Changelog

## 2026-11-10

### Server-rendered audit dashboard

- Added `GET /dashboard` to the collector. It requires a login with the team
  token, issues an HMAC-signed `HttpOnly`/`Secure`/`SameSite=Strict` 12-hour
  session cookie, and renders one HTML page with inline CSS.
- The page shows 24-hour and 7-day blocks, approvals, prompts and per-hour
  rates; per-developer/machine counts; top blocked tools; and machines that have
  not reported in 24 hours. There is no JavaScript framework, external font or
  CDN dependency, and a restrictive CSP blocks external resources.
- Only sanitized event fields are rendered. Added dashboard tests for login,
  cookie flags, aggregation from test data, stale-machine detection, HTML
  escaping, absence of external resources and absence of argument values.

### Audit event shipping and team collector

- Added sanitized audit event shipping from Guard to the team collector. Events
  contain only timestamp, developer/machine ID, server, tool, decision, reason
  code and taint state. The shipped schema has no argument, content, URL or
  free-text field, and the collector rejects unknown fields.
- Added Guard flags `--audit-url`, `--audit-token-file` (falls back to the team
  token), `--audit-ca`, `--audit-id`, `--audit-interval` (default `5s`) and
  `--audit-batch` (default `50`). Events are appended to a disk outbox before
  sending, batched, retried with exponential backoff, and drained after restart.
- Added collector endpoints on `sylenix-teams`: `POST /v1/events` for batches,
  `GET /v1/events` for JSON export and `GET /v1/events/syslog` for RFC 5424
  output. All use the per-team bearer token and append only sanitized events.
- Added `teams/auditevent` (strict schema, RFC 5424 formatting),
  `teams/auditshipper` (outbox, batching, backoff, retry) and collector/API
  tests. The integration test proves events from 3 Guards arrive, offline
  buffering delivers after recovery, and argument text never appears in the
  export, syslog output, outbox or stored log.
- Documented the collector, event schema and audit flags in `teams/README.md`.

### Team policy service (paid tier)

- Added `teams/`, a separate stdlib-only Go package and `bin/sylenix-teams`
  binary. It serves one signed policy per team over HTTPS at `/v1/policy`
  (`GET` to pull, `PUT` to publish), verifies the existing Ed25519 detached
  `.sig` format before storing, and stores only SHA-256 token hashes. The
  `serve`, `token hash` and `publish` commands are available; there is no
  plaintext HTTP mode.
- Added Guard flags `--team-url`, `--team-token-file` (or
  `SYLENIX_TEAM_TOKEN`), `--team-pubkey`, `--team-ca` and `--team-interval`
  (default `15m`). Guard pulls on start and on every interval, verifies the team
  signature, caches the last good policy under `--state-dir`, and fails closed
  when neither a verified pull nor a verified cache is available.
- Policy changes are applied at runtime through an immutable policy snapshot.
  A rejected or tampered refresh keeps the last good policy. Local policy files
  and local flags are overlays that can only tighten the team policy; loosening
  attempts are ignored and recorded as `team_policy_loosen_ignored`.
- Added `teams/policyserver/integration_test.go`: a TLS test service plus three
  real Guard subprocesses prove a policy change is picked up within one pull, a
  tampered served policy is rejected with the last good policy retained, local
  loosening is ignored, and cache/no-cache/tampered-cache paths fail closed.
  Added unit tests for token hashing, envelope handling, authentication and
  stored-signature verification. Added `make team-test` to `make check`, and
  `make build` now builds both binaries.
- Documented the service in `teams/README.md` and added the team-policy
  limitations to `POC_SPIKE.md` section 7.

### Protected targets and proxy Host validation

- Extended the built-in protected-target table with agent config directories
  (`.claude`, `.codex`, `.gemini`, `.continue`), `.ssh`, fish and desktop
  autostart config, `.gitconfig`/`.git/config`, zsh/bash login files,
  package-manager credentials (`.npmrc`, `.pypirc`, `.netrc`) and Guard's own
  `.sylenix-poc`/`.sylenix-keys` state. The active `--state-dir` is resolved at
  startup and protected as well. These targets are `SENSITIVE_TARGET` after
  taint and are never covered by `--allow-write-under` or `--grant`; a scratch
  root inside the state directory is therefore protected too.
- Hardened the Streamable HTTP proxy's `Origin` check: the request `Host` must
  be `127.0.0.1`, `localhost`, `::1` or the exact `--listen` host/port.
  Requests with any other `Host` now get `403` with `ORIGIN_FORBIDDEN`.
- Hardened grant/scratch precedence: `.git/**` (including `.git/hooks`),
  `.env*`, key files and Guard state/key directories are hard-sensitive and
  are blocked before `grantAllows` or `scratchAllows`. Human dialog grants may
  still cover dialog-approvable protected targets such as `AGENTS.md` and
  `CLAUDE.md`. Added dialog-grant and CLI `--grant` regressions, including
  `.git/hooks/pre-commit`.
- Added protected-target categories and a configured state-dir probe to
  `tests/probes/test_protected_targets.py`, and Origin/Host cases to
  `tests/probes/test_http_proxy.py`. Tightened the expected rule for `.ssh`
  paths in `test_scratch_grant_bypass.py` from `TAINT_SINK` to the stricter
  `SENSITIVE_TARGET`, and separated test state directories from scratch roots
  in the affected fixtures.
- Updated README evidence with the November 2026 launch numbers and the
  `results/2026-11-launch.md` link; updated the README, `POC_SPIKE.md` and
  `docs/ARCHITECTURE.md` protected-target and proxy Host descriptions.
- Added `.github/workflows/ci.yml`, running `make check` on Ubuntu, Windows
  (Git Bash) and macOS for every push and pull request.

## 2026-11-09

### Policy and pin signing

- Added Ed25519 signing for `policy.yaml` and `pins-<name>.json`. `keys init`
  creates a PKCS#8/PKIX keypair outside the state directory with a warning that
  the private key can loosen Guard; `policy sign` writes a raw 64-byte detached
  `.sig`, and `policy verify`, `pins sign` and `pins verify` are available for
  pre-signing and diagnostics.
- Added `--policy-pubkey` for verification/team mode and `--policy-key` for
  signing pins on write. If both are set they must match. Once signing is
  enabled, a missing, truncated, wrong-key or one-byte-changed policy or pin
  signature stops the guard with exit 2 before parsing or pinning.
- Public-key-only mode never writes an unsigned pin store; new pins stay in
  memory for that session. `--reset-pins` removes both the pin file and its
  signature. `install`/`allow` remove a stale policy signature after rewriting.
- Extended `doctor --require-signatures` to verify with a wrapper
  `--policy-pubkey` when present, and updated the unsigned-policy/pin findings.
- Added `tests/probes/test_signing.py` (23 checks) and `make signing-test`,
  included in `make check`. Updated `docs/POLICY.md`, `README.md`,
  `docs/ARCHITECTURE.md`, `docs/DOCTOR.md`, `docs/INSTALL.md` and `POC_SPIKE.md`.

### Streamable HTTP proxy

- Added `sylenix-guard proxy --listen ADDR --upstream URL`, reusing the existing
  `Guard` taint, pin, quarantine, hard-block, grant and approval core instead of
  forking it. The listener defaults to `127.0.0.1:8080`; empty/`localhost` hosts
  normalize to loopback.
- Added Streamable HTTP transport handling for MCP 2025-11-25: POST JSON-RPC,
  optional POST SSE and GET SSE, DELETE session termination, `Mcp-Session-Id`
  pass-through, `MCP-Protocol-Version`, Origin validation, and the stateless
  2026-07-28 shape. The legacy 2024-11-05 HTTP+SSE transport is not implemented.
- Client auth headers (`Authorization`, `Cookie`, custom auth keys) are copied
  to the configured upstream but never logged or persisted. Redirects are not
  followed, and the audit `start` event redacts the upstream query string.
- Added `tests/probes/test_http_proxy.py` plus `tests/probes/http_fake_server.py`:
  the stdio and HTTP transports produce the same block sequence; POST/GET SSE,
  server notifications, session IDs, auth pass-through, token non-persistence,
  pin persistence and quarantine are covered. Added `make proxy-test` and
  included it in `make check`.
- Updated `README.md`, `docs/ARCHITECTURE.md`, `POC_SPIKE.md` (post-POC scope
  note) and the build/test docs. Manual initialize/tools-list against
  `https://mcp.deepwiki.com/mcp` succeeds over SSE.

### Doctor

- Added `sylenix-guard doctor [--json] [--policy PATH] [--state-dir DIR]
  [--require-signatures]`. It reads the supported MCP client configs, reports
  each server's transport and whether it is wrapped by Guard, and checks the
  policy allowlist, approval mode, trust list and scratch roots.
- Findings each carry one suggested fix: `NOT_WRAPPED`,
  `REMOTE_NOT_COVERED`, `NOT_ALLOWLISTED`, `ALLOWLIST_NOT_ENFORCED`,
  `ALLOWLIST_HASH_MISMATCH`, `RISKY_SCRATCH` (home, repository root, an
  ancestor of either, a filesystem root, or an unresolvable path),
  `TRUST_ON_EGRESS`, `APPROVALS_OFF`, `UNSIGNED_POLICY`, `UNSIGNED_PINS`,
  `OUTDATED_GUARD`, `GUARD_NOT_FOUND`, `GUARD_VERSION_UNKNOWN`,
  `CONFIG_UNREADABLE`, `SERVER_INVALID`, `WRAPPER_INVALID`, `POLICY_INVALID`
  and `PINS_UNREADABLE`.
- Exit code is 0 with no findings, 1 with findings and 2 for a usage error.
  `--json` prints only the JSON report.
- Doctor is read-only and never prints command arguments, environment values,
  secrets or file contents. It never launches the configured server or Guard
  binary. The probe checks that configs, policy and pins are byte-for-byte
  unchanged and that no audit log is created.
- Guard binaries are versioned with `-X main.version=<tag>`; the default local
  version is `0.1.0` and GoReleaser now injects the release tag. Doctor reads a
  wrapper's version safely from Go build information and also checks the
  `_sylenixGuard` metadata version.
- Policy and pin signing is not implemented yet. `--require-signatures` reports
  an unverified policy or pin file as unsigned instead of assuming it is safe;
  without the flag, unsigned files are not findings so existing setups can
  remain clean.
- Added `docs/DOCTOR.md`, a doctor section in `docs/INSTALL.md`, and README
  and `POC_SPIKE.md` scope/limitation updates.
- Added `tests/probes/test_doctor.py` (99 checks): clean setup, every finding,
  JSON shape, no argument/env leakage and read-only behavior. Added
  `make doctor-test` and included it in `make check`.

### Clear taint and stats

- Added `sylenix-guard clear-taint --name <session> [--state-dir DIR]`. It
  writes a nonce-bound request to the running guard's state directory; the guard
  shows a two-button OS dialog (Deny by default, 60 s timeout) and only a human
  **Clear Taint** click clears the in-memory latch. The CLI has no
  `--yes`/`--force`, and MCP tool calls, host methods, server requests or
  notifications and environment variables cannot clear taint.
- The guard writes a 0600 control file with a random nonce and heartbeat,
  0600 request/result files, rejects stale heartbeats, stale requests and bad
  nonces, and removes the control/request files on exit. The CLI removes its
  result file; stale results are cleaned at the next guard start. A same-user
  process can request a dialog, but cannot clear without human approval.
- Successful clears log `CLEAR_TAINT` with `who` (OS user), event `ts`,
  `method: dialog`, `granted: true` and a random `request_id`. Denials log
  `CLEAR_TAINT_DENIED`; invalid requests log `CLEAR_TAINT_REJECTED`; a clean
  session logs `CLEAR_TAINT_NOT_NEEDED`. No argument values, nonces or secrets
  are logged.
- Added `sylenix-guard stats [--name NAME | --file PATH] [--state-dir DIR]`.
  It mirrors `scripts/summarize_audit.py`, including approval prompts per
  active hour, blocks, approvals, quarantines and unparseable frames. Active
  time excludes gaps over 600 s; prompts/hour is `n/a` below 300 active seconds.
- Verified the existing default that built-in profile read-only tools never
  prompt after taint. The new dialog-mode probe proves reads do not open the
  approval dialog while a write does. An explicit `--readonly` list or policy
  class remains a replacement and is not widened automatically.
- Added `tests/probes/test_clear_taint.py` (64 checks) and
  `tests/probes/test_stats.py` (21 checks), plus `make clear-taint-test` and
  `make stats-test`, both part of `make check`.
- Extended `demo/fake_server.py` with an unknown-method error response and an
  opt-in `sylenix/clear-taint` server request/notification for the isolation
  probes.
- Updated README and POC_SPIKE scope, verification and limitations, including
  the new human-approved clear path and the local control-file boundary.

## 2026-11-08

### Policy file

- Added a versioned policy file (`version: 1`). Location order is `--policy
  PATH`, then `<state-dir>/policy.yaml`, then built-in defaults. A file that
  exists but cannot be read or parsed is a startup error; the guard never falls
  back to a weaker policy.
- Added per-server/per-tool classes (`read`, `write`, `exec`, `egress`),
  optional per-tool `path_keys` and `allow_paths`, optional per-tool `trust`,
  global `sensitive_paths`, `egress.allow_hosts`/`deny_hosts`, `approval` and
  `spotlight`. Unknown tools default to `exec`. Unknown fields, duplicate keys,
  unsupported YAML features, bad versions/classes/patterns and a missing
  `servers.<name>` entry fail closed with exit 2.
- The built-in sensitive-name list now lives in the policy defaults and can be
  extended by `sensitive_paths`; it cannot be removed. The `.git/hooks`
  protected-target exception remains.
- Added `sylenix-guard policy validate <file>` and `sylenix-guard policy
  print-default`. The loader accepts a strict YAML subset and JSON.
- `--readonly`, `--trust`, `--approve`, `--allow-write-under` and
  `--no-spotlight` still work, override the corresponding policy section when
  explicitly set, and print a deprecation note pointing at the policy
  equivalent. `--grant` remains flag-only.
- Added `docs/POLICY.md` with the schema, decision table, precedence rules and
  three examples. Updated README and POC_SPIKE scope/limitations.
- Added `tests/probes/test_policy.py` (validation failures, auto-load and
  explicit-path precedence, classes, unknown tools, path keys, allow paths,
  egress allow/deny, trust/spotlight, flag precedence, deprecation notes and
  audit non-logging) and wired it into `make check`.
- `demo/selftest.py` now runs in flags mode or `--policy` mode; `make check`
  runs both. No existing check was weakened, deleted or skipped.

### Built-in policy profiles

- Added profiles for filesystem, git, GitHub, fetch, shell, Slack, Postgres,
  browser (Playwright/Puppeteer), Notion and Jira. Each tool in each profile is
  classified `read`, `write`, `exec` or `egress`, with the source package and
  version cited in `cmd/sylenix-guard/main.go`.
- Profiles are selected automatically from the server command/package/image
  token, with `--name` as a fallback. A policy file may set `profile: auto`
  (default), `profile: none`, or `profile: <name>`, and any per-tool policy entry
  overrides the profile class.
- Added `tests/probes/test_profiles.py`: every profile must allow a read after
  taint and block a write or egress call, plus per-tool override, `profile:
  none`, and explicit-profile checks.
- Added `scripts/replay_profile_session.py` and
  `demo/fixtures/normal_session.json`. The recorded 60-minute filesystem session
  reports 1 approval prompt (1/hour), below the 10/hour budget.
- Added `make profile-test` and `make replay-test`, both part of `make check`.

### Server command allowlist

- Added `allowlist_enforced` and `allowlist` to the policy file. Each entry
  matches the exact command and argument list, supports `*`/`?` argument
  patterns, and may carry a SHA-256 of the resolved binary or of a `lockfile`.
- The guard checks the allowlist before creating the child process. An
  unapproved command exits 2, writes `SERVER_NOT_ALLOWED` to the audit log, and
  prints how to approve it. The audit event records the command path and reason,
  never the argument values.
- Added `sylenix-guard allow <name>`, which reads the named server from the
  supported MCP client configs, shows the exact command and arguments, asks for
  confirmation, computes a binary hash when possible, and writes the policy
  entry.
- `install` now pre-populates `<state-dir>/policy.yaml` with the servers present
  at install time, enables enforcement, and asks for confirmation unless
  `--yes`. Added `--policy` and `--state-dir` to install and pinned them in the
  wrapper it writes, so the installed server loads the same policy.
- Added `tests/probes/test_allowlist.py`: unapproved refusal, approved launch,
  changed binary hash, changed lockfile hash, `allow`, and install
  pre-population. Extended policy validation probes for malformed allowlists.
- Updated `docs/POLICY.md` with the allowlist schema and commands.

### Security

- Tightened `--allow-write-under` and `--grant`: only values under known path
  keys are treated as paths. Any other non-content value that looks like a
  path, a hidden file/directory, a home-relative path, a drive-relative path or
  another destination now disqualifies the call from both fast paths.
- Sensitive-path detection now checks non-content values under any key and
  normalises both `/` and `\`. Destination-named keys such as `host`, `server`,
  `to`, `recipient` and `callback` are hard-blocked once the session is tainted,
  even when the value is a bare name rather than a URL.
- Path comparison now expands `~`, resolves symlinks and `..` in operating
  system order, rejects drive-relative paths, handles Windows drive letters and
  UNC shapes, folds case only when the filesystem is case-insensitive, and
  refuses a fast path if the approved root itself changes identity during the
  session.
- Added a single protected-target table for agent instructions and persistence:
  `AGENTS.md`/`CLAUDE.md`/`GEMINI.md`, Cursor/Windsurf rules, MCP/editor config,
  `.vscode`, `.idea`, CI workflows, `.gitlab-ci.yml`, `.git/hooks`, `.husky`,
  shell startup profiles, cron, launchd, systemd user units and Windows Startup.
  These are `SENSITIVE_TARGET` after taint, never use a grant or scratch
  shortcut, and can only proceed through `--approve dialog`.
- Server-to-client requests and notifications that carry text or resource
  content now latch taint with reason `TAINT_SERVER_REQUEST` before the host
  sees them. This covers sampling, elicitation, logging messages and resource
  content; only the method and reason code are logged, never the content.

### Repository

- `make build` now also builds `bin/sylenix-guard.exe` on Windows, so
  `make check` exercises the same binary that MCP clients resolve through
  `PATHEXT`.
- Added the Apache License 2.0 `LICENSE` (Copyright 2026 Sylenix Labs) and the
  SPDX header to the Go source.
- Added `SECURITY.md` for private bypass reporting, response expectations and
  safe harbour.
- Added `CONTRIBUTING.md` with build/check commands, the no-weakening rule for
  tests and probes, and the pull-request checklist.
- Added a "Security model and limits" section to `README.md` linking to
  `SECURITY.md`.

### Installer

- Added `sylenix-guard install` and `sylenix-guard uninstall` for existing
  Claude Desktop, Claude Code, Cursor and VS Code configs on macOS, Windows and
  Linux. Stdio entries are wrapped with the Guard executable while preserving
  the original command, argument order and environment. The commands support
  `--yes` and `--dry-run`, write timestamped backups, show a diff before
  writing, and restore from the wrapped entry itself on uninstall.
- Added `docs/INSTALL.md` with the exact config paths and wrapper format.
- Added `tests/probes/test_install.py` covering round-trips, dry-run, backups,
  already-wrapped and remote entries, and broken configs.

### Releases

- Added GoReleaser configuration and a tag-only GitHub Actions workflow.
  Builds cover darwin/linux amd64+arm64 and windows amd64, with SHA-256
  checksums, Cosign keyless signature bundles, Syft SBOMs, a Homebrew formula
  and a Scoop manifest.
- The release job runs `make check` and the protocol self-test first. Formula
  and manifest publishing use optional tap/bucket tokens; without them the
  generated files remain local/release artifacts.
- Added release verification steps to `docs/INSTALL.md`.

### Tests

- Added `tests/probes/test_scratch_grant_bypass.py`: ten tainted-session probes run
  under both `--allow-write-under` and `--grant`, plus a symlink/junction escape
  created after startup, sensitive/egress controls and legitimate scratch-write
  cases.
- Added `tests/probes/test_protected_targets.py`: every protected-target category
  is checked before taint (allowed) and after taint (blocked), under scratch and
  scoped grant, with an optional fake-zenity approval check on Linux.
- Extended `demo/fake_server.py` and `demo/selftest.py` with a sampling request
  carrying injected text followed by an egress call; the call is blocked and the
  audit records `TAINT_SERVER_REQUEST` without the content.
- Added the `probe-test` Make target and included it in `make check`.
- `summary-test` now strips carriage returns before the fixture diff, so
  `make check` also passes under the Git Bash shell on Windows.
