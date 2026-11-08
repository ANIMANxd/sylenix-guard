# Changelog

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
