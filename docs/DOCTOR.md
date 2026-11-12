# `sylenix-guard doctor`

`doctor` audits the MCP client configurations that Guard knows about. It answers
one question: **what is actually protected on this machine?**

It never launches an MCP server or a Guard binary, never writes a config,
policy or pin file, and never prints command arguments or environment values.
The report contains server names, Guard flags, file paths, tool names and
reason codes only.

```bash
sylenix-guard doctor
sylenix-guard doctor --json
sylenix-guard doctor --policy ./policy.yaml --state-dir ./.state
sylenix-guard doctor --require-signatures
```

Exit code:

| Code | Meaning |
|---|---|
| `0` | No findings. |
| `1` | At least one finding. |
| `2` | Usage error, such as an unknown flag or an empty `--policy`. |

`--json` prints only the JSON report on stdout. A broken config is a finding in
the report, not a crash.

## Flags

| Flag | Meaning |
|---|---|
| `--json` | Machine-readable report. |
| `--policy PATH` | Check this policy for every server instead of the wrapper's `--policy`, the wrapper's `<state-dir>/policy.yaml`, or the default. |
| `--state-dir DIR` | State directory used when a wrapper does not pin one. Default `~/.sylenix-poc`. |
| `--require-signatures` | Report policy and pin files that cannot be verified. Doctor uses the wrapper's `--policy-pubkey` when present; without a key, a signed or unsigned file is reported as unsigned and never assumed safe. |

## Configs it reads

Doctor uses the same discovery as `install` and `allow`:

| Client | Path |
|---|---|
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` / `~/Library/Application Support/Claude/...` / `$XDG_CONFIG_HOME/Claude/...` |
| Claude Code (user) | `~/.claude.json` |
| Claude Code (project) | `./.mcp.json` |
| Cursor (user) | `~/.cursor/mcp.json` |
| Cursor (project) | `./.cursor/mcp.json` |
| VS Code settings | `%APPDATA%\Code\User\settings.json` / `~/Library/Application Support/Code/User/settings.json` / `$XDG_CONFIG_HOME/Code/User/settings.json` (`mcp.servers` or `mcpServers`) |
| VS Code user MCP | `%APPDATA%\Code\User\mcp.json` / `~/Library/Application Support/Code/User/mcp.json` / `$XDG_CONFIG_HOME/Code/User/mcp.json` (`servers` or `mcpServers`) |
| VS Code workspace | `./.vscode/mcp.json` (`servers` or `mcpServers`) |

Relative wrapper paths are resolved against doctor's working directory. Run
doctor from the same directory the client uses, or use absolute paths (install
writes absolute paths).

## What it reports per server

- whether the entry is a stdio or remote transport;
- whether it is wrapped by Guard;
- whether its command and arguments match the policy allowlist;
- the effective approval mode, trusted tools and scratch roots;
- the policy file used.

A Guard wrapper is recognized by the `_sylenixGuard` metadata written by
`install`, or by a command whose base name is `sylenix-guard` /
`sylenix-guard.exe`. A renamed hand-written wrapper without the metadata is
reported as unwrapped. Re-run `install` to add the metadata.

## JSON shape

`--json` prints one object. `configs` lists every detected config and server;
`findings` is empty when the setup is clean. Command arguments and environment
values are never included.

```json
{
  "version": "0.1.1",
  "clean": false,
  "configs": [
    {
      "client": "Claude Code",
      "path": "/home/me/.claude.json",
      "servers": [
        {
          "name": "demo",
          "map": "mcpServers",
          "transport": "stdio",
          "wrapped": true,
          "allowlisted": false,
          "approval": "deny",
          "policy": "/home/me/.sylenix-poc/policy.yaml"
        }
      ]
    }
  ],
  "findings": [
    {
      "code": "NOT_ALLOWLISTED",
      "severity": "risk",
      "client": "Claude Code",
      "config": "/home/me/.claude.json",
      "server": "demo",
      "detail": "server command and arguments are not in the policy allowlist",
      "fix": "run `sylenix-guard allow \"demo\"`"
    }
  ]
}
```

Optional server fields are omitted when empty: `approval`, `trusted_tools`,
`scratch_dirs`, `policy` and `error`. A config-level `error` means the file
could not be inspected; a server-level `error` means that entry is invalid or
its policy could not be used. `severity` is `error` for a file or entry that
cannot be used and `risk` for a configuration weakness.

## Findings

| Code | Meaning | Suggested fix |
|---|---|---|
| `NOT_WRAPPED` | A stdio server is not wrapped by Guard. | Run `sylenix-guard install` or wrap the entry manually. |
| `REMOTE_NOT_COVERED` | The server uses HTTP/SSE/WebSocket transport, which `install` cannot wrap automatically. | Configure `sylenix-guard proxy --upstream <url>` manually, or use a local stdio server. |
| `NOT_ALLOWLISTED` | The server command and arguments do not match any policy allowlist entry. | Run `sylenix-guard allow <name>` (or `install`). |
| `ALLOWLIST_NOT_ENFORCED` | The policy has an allowlist but `allowlist_enforced` is false. | Set `allowlist_enforced: true` and keep exact entries. |
| `ALLOWLIST_HASH_MISMATCH` | A matching allowlist entry has a `sha256` that does not match the resolved command or lockfile, or the hash target cannot be read. With the allowlist enforced, the guard would refuse to launch. | Re-run `sylenix-guard allow <name>` to refresh the hash. |
| `RISKY_SCRATCH` | `--allow-write-under` or policy `allow_paths` covers the home directory, the repository root, an ancestor of either, a filesystem root, or a path that cannot be resolved. | Narrow it to a project subdirectory, for example `<repo>/out`. |
| `TRUST_ON_EGRESS` | A trusted tool is configured on a server that has at least one egress-class tool. Results from trusted tools do not latch taint. | Remove `--trust` / `trust: true` for that server. |
| `APPROVALS_OFF` | Effective approval mode is `deny`, so the OS dialog is disabled and tainted sinks are hard-blocked rather than reviewed. | Set `--approve dialog` in the wrapper or `approval: dialog` in the policy. |
| `SHARED_TAINT_OFF` | A client config wraps two or more servers but at least one wrapper has no non-empty `SYLENIX_SESSION` environment value or `--session` flag, so taint is not shared across those processes. | Re-run `sylenix-guard install`, or add `SYLENIX_SESSION` to every wrapped entry. |
| `UNSIGNED_POLICY` | `--require-signatures` was set and the policy has no valid signature for the configured public key. | Sign with `policy sign` and add `--policy-pubkey` to the wrapper. |
| `UNSIGNED_PINS` | `--require-signatures` was set and the pin file has no valid signature for the configured public key. | Sign with `pins sign` or run with `--policy-key` so new pins are signed. |
| `OUTDATED_GUARD` | The wrapper metadata version is older than this build, or the Guard binary in the wrapper is older than the running doctor. | Upgrade Guard and re-run `sylenix-guard install`. |
| `GUARD_NOT_FOUND` | The wrapper points at a Guard command that does not exist or is not on `PATH`. | Install Guard there or re-run `sylenix-guard install`. |
| `GUARD_VERSION_UNKNOWN` | The Guard binary is not a readable Go binary, is not a Sylenix Guard binary, has no embedded version, or reports a version that cannot be compared. | Point the config at the Guard binary or reinstall from a release. |
| `CONFIG_UNREADABLE` | The config cannot be inspected, is a directory, has duplicate JSON keys, is not valid JSON, or a server map is not an object. | Repair the config; the guard refuses ambiguous configs. |
| `SERVER_INVALID` | A server entry is not an object, has no non-empty string command, has a command with surrounding spaces, has a non-array/non-string `args`, has an unsupported type, or has an empty/control-character name. | Make it a stdio entry with a string command and a string args array. |
| `WRAPPER_INVALID` | A Guard wrapper has no `--` separator, an unknown or malformed Guard flag, malformed `_sylenixGuard` metadata, no server command after `--`, or a wrapped server command with control characters or surrounding spaces. | Re-run `sylenix-guard install` or fix the Guard flags. |
| `POLICY_INVALID` | The policy cannot be read or validated, or has no entry for the effective server name. | Run `sylenix-guard policy validate <file>` and fix it. |
| `PINS_UNREADABLE` | The pin file exists but is not a regular file, is too large, cannot be read, or is not a JSON map of SHA-256 hashes. The guard refuses to start in this state. | Inspect the file, or restart with `--reset-pins`. |

## Version check

Doctor compares the Guard binary referenced by a wrapper with the running
doctor. It reads the Go build information (`debug/buildinfo`) and the
`-X main.version=...` linker setting; it does not execute the configured
binary. Release builds set that value in `.goreleaser.yaml`. A local build
without the linker flag has no embedded version and is reported as
`GUARD_VERSION_UNKNOWN` when it differs from the running doctor.

A development build of doctor cannot compare versions and does not claim a
wrapper is outdated. It only reports a binary whose version cannot be read or
parsed.

## Unsigned policy and pins

`--require-signatures` verifies a policy or pin file when the wrapper carries a
`--policy-pubkey`. A missing, truncated, wrong-key or one-byte-changed signature
is reported as `UNSIGNED_POLICY` / `UNSIGNED_PINS`; doctor never treats the
absence of a signature as safe. Without a public key it reports the file as
unsigned because it cannot verify it. Without the flag, unsigned files are not
findings, so existing setups can remain clean.

## What it does not do

- It does not execute the server or the Guard binary, so it cannot test whether
  a server actually starts.
- It does not cover host built-in tools, attachments, pasted text or any
  traffic that never passes through Guard.
- It does not detect a renamed hand-written Guard wrapper without the
  `_sylenixGuard` metadata.
- It does not resolve DNS, inspect a server's actual tool list, or verify a
  runtime tool manifest. It audits configuration, not a live session.
- It does not replace a policy review. A server can be wrapped and allowlisted
  and still be a poor trust decision (`--readonly`, `--trust`, `class: read`).
