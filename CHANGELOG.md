# Changelog

## 2026-11-08

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

### Tests

- Added `tests/probes/test_scratch_grant_bypass.py`: ten tainted-session probes run
  under both `--allow-write-under` and `--grant`, plus a symlink/junction escape
  created after startup, sensitive/egress controls and legitimate scratch-write
  cases.
- Added `tests/probes/test_protected_targets.py`: every protected-target category
  is checked before taint (allowed) and after taint (blocked), under scratch and
  scoped grant, with an optional fake-zenity approval check on Linux.
- Added the `probe-test` Make target and included it in `make check`.
- `summary-test` now strips carriage returns before the fixture diff, so
  `make check` also passes under the Git Bash shell on Windows.
