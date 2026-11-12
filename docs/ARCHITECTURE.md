# Sylenix Guard Architecture

This document maps the code as it exists today. It is descriptive, not a
roadmap. The source of truth for scope is `POC_SPIKE.md`; the full product
intent is in `docs/SPEC_FULL.md`.

## 1. Shape of the system

The Guard proxy is one Go binary (`cmd/sylenix-guard/main.go`, package `main`)
with no third-party modules. The proxy core uses the standard library and the
optional paid-tier policy/audit features use in-repo packages under `teams/`.
The paid-tier service is a separate binary (`teams/cmd/sylenix-teams`) that uses
the same in-repo packages. Guard supports two transports for exactly one MCP
server per process:

```text
stdio:
MCP host  <--- stdin/stdout --->  sylenix-guard  <--- child stdin/stdout --->  MCP server
                                      |
                                      +--- stderr (inherited from the server)
                                      +--- state dir: pins, audit, control files

Streamable HTTP:
MCP client <--- HTTP/SSE --->  sylenix-guard  <--- HTTP/SSE --->  remote MCP server
                                      |
                                      +--- state dir: pins, audit, control files
```

In both modes the guard reads one JSON-RPC message, inspects or rewrites it,
forwards it, and returns responses unchanged except for datamarking. `initialize`
is passed through unchanged; the guard does not negotiate or enforce an MCP
protocol version. The stdio self-test uses `2025-06-18` in its handshake
(`demo/selftest.py`); the HTTP probes use `2025-11-25`.

The same binary also contains the non-proxy subcommands: `install`, `uninstall`,
`policy`, `allow`, `doctor`, `clear-taint`, `stats`, and `version`. `main`
dispatches those before parsing proxy flags. `--version` and `version` print the
build string and return before any server-launch path.

### 1.1 Streamable HTTP proxy mode

`proxy` is a separate transport front end over the same `Guard` decision core:

- `--listen` defaults to `127.0.0.1:8080`; an empty host or `localhost` is
  normalized to `127.0.0.1` (`normalizeListenAddr`).
- `--upstream` is required and must be an absolute `http` or `https` URL. Its
  query string is forwarded to the upstream but redacted from logs and audit
  events (`redactURL`).
- `POST` carries one JSON-RPC message. `GET` opens the optional server-to-client
  SSE stream. `DELETE` terminates the upstream session. `OPTIONS` answers
  locally (`ServeHTTP`).
- `Origin` and `Host` are checked before any request is forwarded. The request
  `Host` must be `127.0.0.1`, `localhost`, `::1` or the exact `--listen` address.
  Missing Origin is allowed; loopback origins and the request host are allowed;
  anything else gets HTTP 403 (`originAllowed`, `hostHeaderAllowed`).
- Request headers are copied end to end except hop-by-hop headers, `Host`,
  `Content-Length`, `Accept-Encoding`, and `Origin` (`copyRequestHeaders`).
  `Authorization`, `Cookie`, `Mcp-Session-Id`, `MCP-Protocol-Version`, and
  `Last-Event-ID` therefore reach the upstream.
  Header values are never logged.
- `Mcp-Session-Id` is passed through in both directions. The proxy does not
  mint, store, or persist session IDs. This is valid for the session-bearing
  MCP 2025-11-25 revision; it also works with the stateless 2026-07-28 shape
  because the header is simply absent.
- Upstream `content-type: application/json` bodies are inspected by
  `fromServer` and returned as JSON. `text/event-stream` bodies are parsed event
  by event, inspected by `fromServer`, and re-emitted as SSE (`streamSSE`). SSE
  comments, `event:`, `id:`, `retry:` and multi-line `data:` fields are
  preserved.
- A blocked host message returns a JSON-RPC error immediately without contacting
  the upstream (`handlePost`). A notification that the guard drops
  gets HTTP 202.
- Upstream failures and oversized frames fail the pending request with
  `UPSTREAM_ERROR`, `SERVER_FRAME_TOO_LARGE`, or `SERVER_STREAM_CLOSED` rather
  than leaving the client waiting (`failOne`; `finishPending`).

The legacy HTTP+SSE transport from 2024-11-05 (separate SSE and POST endpoints)
is not implemented. `install` still skips remote config entries, and `doctor` reports them as
`REMOTE_NOT_COVERED` because installing a remote transport is a
client-configuration decision, not a wrapper decision; the finding now points at
manual `proxy` configuration.

### 1.2 Signing policy and pin stores

Signing is an Ed25519 detached-signature layer over the exact bytes of
`policy.yaml` and `pins-<name>.json`:

- `keys init` generates a PKCS#8 private key and PKIX public key
  (`runKeysCommand`). The default path is outside the state
  directory, `~/.sylenix-keys/policy-signing.key`; a key inside the configured
  state directory is refused. The private key is written `0600` and the command
  prints a warning that anyone who can read it can loosen Guard.
- `policy sign --policy PATH --key PATH` validates the policy and writes
  `policy.yaml.sig`, a raw 64-byte signature (`runPolicySignCommand`,
  `signFileDetached`). `policy verify` and `pins sign` / `pins verify` cover
  diagnostics and pre-signing (`runPolicyVerifyCommand`, `runPinsCommand`).
- `--policy-pubkey` loads the verification key; `--policy-key` loads the private
  key, derives its public key and enables signing of new pin stores. If both are
  set, the public keys must match (`loadGuardSigningKeys`).
- Policy verification happens in `loadPolicyForRun` before parsing. Pin
  verification happens in `loadPins` before JSON parsing and hash validation. A
  missing, truncated, wrong-key or changed signature returns an error and the
  process exits 2.
- `savePins` signs the exact JSON bytes before writing the store. Without a
  private key but with verification enabled it keeps pins in memory and does
  not write an unsigned store. `--reset-pins` removes both the pins and the
  `.sig`.
- `writePolicyFile` and `writeDefaultPolicyFile` remove a stale policy
  signature after any canonical rewrite, so `install` and `allow`
  leave a fail-closed missing signature rather than a valid-looking stale one.

This detects modification, not rollback: an older signed policy/pin pair can be
restored. The private key is only as safe as its file permissions and the
machine account; there is no HSM or remote signer.

## 2. Entry point and startup sequence

`main` is at `cmd/sylenix-guard/main.go`.

1. Subcommand dispatch. If `os.Args[1]` is a known subcommand, run it and exit.
   `version`, `--version`, and `-version` print the build string and return
   before any server launch. Otherwise fall through to proxy mode.
2. Proxy flag parsing. `flag.Visit` records which flags were
   explicitly supplied, so flags can override policy only when the
   operator actually set them.
3. Input validation and flag expansion:
   - `--approve` must be `deny` or `dialog` when explicitly set.
   - `--allow-write-under` becomes `[]scratchRule`, with `TOOL=DIR` support.
   - `--grant` becomes seeded non-protected in-memory grants, with
     `TOOL[:DIR]=DURATION` parsing.
4. Name and state-directory defaults. The default name is the
   server command's basename; the default state directory is `~/.sylenix-poc`.
5. State directory creation with mode `0700` and audit-log open with mode
   `0600`.
6. Signing-key load and `Guard` construction.
7. Policy resolution and application: explicit `--policy`, else
   `<state-dir>/policy.yaml`, else built-in defaults; signature verification when
   a key is configured; profile selection; flag overrides.
8. Server allowlist check before the child is launched. A refusal
   exits `2` and writes `SERVER_NOT_ALLOWED` to the audit log.
9. Pin-file load; an untrusted pin file exits `2` unless `--reset-pins`.
10. Child process start with stdin/stdout pipes; stderr is inherited.
11. Start event and clear-taint control loop.
12. Signal handler, then two long-lived goroutines: host-to-server
     and server-to-host.
13. Wait for the server-to-host loop and the child, stop the control loop, log
    the exit, and exit with the child's code.

The child is killed five seconds after either side closes its input, on a
signal, or when the guard shuts down.

Proxy mode shares steps 3 through 9 through `prepareGuard`. It then
binds the listener (`runProxyCommand`), starts the same clear-taint
control loop, emits a `start` event with `transport: streamable-http`, and serves
HTTP until a signal or listener error. It does not check the server-command
allowlist because there is no child command to launch; the stdio allowlist
remains a launch-only control.

## 3. Main data structures

All in `cmd/sylenix-guard/main.go`:

| Type | Purpose | Location |
|---|---|---|
| `Guard` | Entire per-process state: policy, taint, pending requests, pins, quarantines, grants, output writer, audit writer | `main.go` |
| `guardOptions` | Shared startup configuration for stdio and HTTP | `main.go` |
| `frame` | `map[string]json.RawMessage` for one JSON-RPC object | `main.go` |
| `pendingReq` | Tracks the method and tool name for an outstanding request id | `main.go` |
| `scratchRule` | One `--allow-write-under` entry: optional tool plus directory | `main.go` |
| `grant` | One time-bounded approval: tool, optional directory, exact protected files, expiry, human/protected flags | `main.go` |
| `policyFile` | Strict on-disk policy schema | `main.go` |
| `policyTool` | Per-tool class, extra path keys, allow paths, trust | `main.go` |
| `policyProfile` | Built-in classification table for a known server family | `main.go` |
| `guardFlagValues` | Common proxy flags registered by both dispatch paths | `main.go` |
| `sseEvent` | One parsed server-sent event | `main.go` |
| `proxyHandler` | HTTP transport state: Guard, upstream URL, HTTP client | `main.go` |
| `guardControl` | Clear-taint control-file implementation | `main.go` |
| `controlFile`, `clearRequest`, `clearResult` | On-disk control/request/result JSON shapes | `main.go` |

Concurrency boundaries:

- `Guard.mu` protects taint state, `pending`, `pins`, `quarantined`, and
  `grants`. Policy maps are built before the goroutines start and
  are read-only afterwards.
- `Guard.outMu` serializes every write to the host's stdout.
  Proxy mode points `out` at `io.Discard`; responses go through the HTTP handler.
- `Guard.logMu` serializes audit-log writes.
- `serverGone` is an `atomic.Bool` set when the server's stdout closes.

## 4. Request path: host -> Guard -> server

In stdio mode the host reader is `readFrame`, called in the host goroutine. It
enforces the 10 MiB frame limit and a 64 MiB discard budget. Oversize host
frames are answered with `-32600 FRAME_TOO_LARGE` and id `null`; the connection
survives unless the line cannot be framed.

In HTTP mode the POST body is bounded by the same `maxFrame` and passed to the
same `fromHost` (`handlePost`). The explicit-allow branch then sends
the original body to the upstream. Blocked requests get a JSON-RPC error body
with HTTP 200; notifications get HTTP 202. The HTTP transport never calls
`Guard.write`, so the stdio writer is not involved.

`Guard.fromHost` decides every host frame:

1. **Batch frames**: top-level `[` is refused with `-32600
   BATCH_UNSUPPORTED`; not forwarded.
2. **Malformed JSON**: `-32700 UNPARSEABLE`, id `null`; not
   forwarded.
3. **Duplicate keys anywhere in the JSON object**: `-32600
   DUPLICATE_KEYS`, id `null`; not forwarded. This is a deliberate parser
   differential defense.
4. **Host responses to server requests**: a frame with no
   `method` is forwarded as a response without further inspection.
5. **Server already gone**: requests get `-32000
   SERVER_STREAM_CLOSED`; notifications get no reply.
6. **Duplicate pending id**: `-32600 DUPLICATE_ID`, id `null`;
   the first request keeps its identity.
7. **Non-`tools/call` methods**: tracked by id, then forwarded.
8. **`tools/call` parsing**: missing or non-object `params`, or
   an empty tool name, gets `-32000 UNPARSEABLE_CALL`.
9. **Quarantine**: a quarantined tool is blocked with `-32001
   MANIFEST_QUARANTINE`, even in a clean session.
10. **Clean session or read-class tool**: forwarded. The class is
    `read` if the tool is in `--readonly`, a profile read default, or policy
    `class: read` (`classFor`). This check is before every hard
    block.
11. **Tainted non-read call** is decided in this order:
    1. **`EGRESS_TARGET`**: any network-shaped argument, unless
       every parsed host is on the policy egress allowlist and none is on the
       denylist. The hard block is not dialog-approvable and is not covered by a
       grant or scratch rule.
    2. **`SENSITIVE_TARGET`**: any sensitive path match. Also not
       dialog-approvable, grant-covered, or scratch-covered.
    3. **Protected persistence/agent-instruction target**: if the
       target is protected and approval mode is not `dialog`, block with
       `SENSITIVE_TARGET`. With `--approve dialog`, it can reach a human.
    4. **Egress allowlist shortcut**: an `egress`-class tool whose
       every destination is allowlisted can run without a prompt, unless the
       call is ambiguous or protected.
    5. **Live grant** (`grantAllows`): a
       time-bounded grant can allow the call only when there is no egress and no
       ambiguity. A protected grant matches only the exact canonical files it
       recorded; a non-protected grant requires every path to stay inside its
       directory (or be tool-wide with resolvable paths). Protected calls never
       use a non-protected grant.
    6. **Scratch write** (`scratchAllows`): no
       prompt while every path stays inside an `--allow-write-under` root. No
       recognizable path means no scratch shortcut.
    7. **Dialog** (`askHuman`): with
       `--approve dialog`, offer Deny / Allow Once / Allow Tool for 15m.
       A protected grant records the exact files; other grants record a
       directory scope. Both are held in memory.
    8. **Default deny**: `-32000 TAINT_SINK`.

A blocked request gets an error frame only when it has an id; notifications are
dropped silently (`replyIfRequest`). Error data carries only a rule
name (`errorFrame`).

## 5. Response path: server -> Guard -> host

In stdio mode the server reader is the same `readFrame` logic.
Oversize server frames cannot be inspected or matched to a request, so the guard
latches taint, fails every pending request with `-32000 SERVER_FRAME_TOO_LARGE`,
and discards the frame.

In HTTP mode JSON bodies are read with the same limit and passed to `fromServer`
(`handlePost`). SSE responses are parsed by `streamSSE`: each `data:` payload
is passed to `fromServer`, and the resulting message is re-emitted with its
`event:`/`id:`/`retry:` fields. A stream that ends
without the pending response gets a synthetic `SERVER_STREAM_CLOSED` error event
(`finishPending`).

`Guard.fromServer` handles a server line:

1. **Unparseable server output**: forwarded unchanged and taints
   with origin `unparseable_server_output`.
2. **Server request or notification**: forwarded so the host can
   answer. If it carries text/resource content, the guard logs only the method
   and rule and latches with reason `TAINT_SERVER_REQUEST`.
   The check is `serverMessageHasContent`; `sampling/createMessage` and
   `elicitation/create` always count, other methods are inspected against
   content-key names.
3. **Response matching**: the id is removed from `pending`. An
   unmatched response is forwarded unchanged and taints with origin
   `unmatched_response`.
4. **`tools/list`**: `inspectToolsList` pins or quarantines tool
   definitions before the line is forwarded.
5. **`tools/call`, `resources/read`, `prompts/get`**: a
   `tools/call` result for a `--trust`ed tool is forwarded without taint or
   datamarking. Every other such result latches taint *before* the host can see
   it. `tools/call` text results are datamarked when spotlighting is enabled;
   resource and prompt results are not wrapped.
6. **Everything else** is forwarded unchanged.

`datamark` wraps each `text` content item in
`<untrusted_tool_result origin="..." integrity="untrusted">`, neutralizes the
literal lower-case closing tag, strips invisible characters, and strips
invisible characters from `structuredContent` strings without wrapping the
structured value. If the result shape is not the expected object/content array,
it returns the original line; taint has already been latched.

## 6. Taint lifecycle

Taint is in memory only. It begins clean in each new guard process.

**Set** by `latch` / `latchReason`. The first latch records the
origin and emits `taint_latched`; later latches only set the boolean.

Triggers:

| Trigger | Code |
|---|---|
| Untrusted `tools/call` result | `fromServer`; `--trust` bypasses only this branch |
| `resources/read` or `prompts/get` result | `fromServer` / `main.go` |
| Unparseable server stdout line | `fromServer` / `main.go` |
| Server response whose id matches no pending request | `fromServer` / `main.go` |
| Server request/notification carrying content | `serverMessageHasContent` |
| Oversize server frame | `readFrame` (server loop) |

**Cleared** only by `clearTaint`, which is called only from the
human-approved clear-taint control path. A successful clear emits
`CLEAR_TAINT` with `who`, `method: dialog`, and a request id. It does not revoke
grants, quarantines, or the server process. MCP tool calls, host methods, server
messages, and environment variables cannot clear the latch.

The `clear-taint` CLI writes a nonce- and guard-start-bound request
file into the state directory and waits for the running guard's result. The
guard polls every 200 ms, validates version, nonce, start time,
request age, and request id, then shows an OS dialog
(`askClearTaint`). Denial, timeout, or an unavailable dialog keeps
the latch.

## 7. Tool pinning and quarantine

On a `tools/list` response, `inspectToolsList` does the following
for each tool with a non-empty name:

1. Marshal the decoded tool object to JSON. Go sorts map keys, so the encoding
   is stable for the same decoded value.
2. SHA-256 the encoding and hex-encode it.
3. Compare with the pin map (`old, seen:= g.pins[name]`).
4. Quarantine if the tool contains invisible characters (`containsInvisible`)
   or if a previously seen definition now has a different hash.
5. Otherwise remove any old quarantine for that name, and if this is first
   sight, store the hash and emit `tool_pinned`.

Quarantine is a tool-name map to a reason string. A quarantined tool is blocked
before taint is even considered. If a later `tools/list` returns
the original pinned definition again, the `delete(g.quarantined, name)` call
removes the quarantine.

The pin file is `pins-<name>.json`. `loadPins` treats a
missing file as first use, but refuses to start if the file exists and is
unreadable, is not a JSON object, has an empty tool name, or has a value that is
not a 64-character hex SHA-256. `--reset-pins` deletes the file and logs
`pins_reset`. `savePins` writes indented JSON and, when a private
key is configured, a detached signature.

## 8. EGRESS and SENSITIVE classification

Classification happens only for a tainted, non-read `tools/call`, in
`scanArgs`. `callScan` records paths, whether an
egress target was seen, parsed egress hosts, sensitive matches, protected
matches, and ambiguity.

The argument key sets are fixed:

- `contentKeys` are never treated as paths or network targets.
- `urlKeys` always imply egress.
- `destinationKeys` imply egress even for a bare hostname.
- `pathKeys` are the only values treated as paths for grants and
  scratch rules. Policy `path_keys` can add per-tool keys.
- `egressSchemes` covers `http`, `https`, `ftp`, `ftps`, `sftp`,
  `ssh`, `smb`, `nfs`, `ws`, `wss`, `mailto`, and `file`.

For a string value, `scanArgs` checks in order: content key, URL/destination
key or URL/URI/IP shape, path key, host:port shape, protected target, sensitive
path, then path-like or path-syntax ambiguity. An ambiguous
non-content value disqualifies grants and scratch rules, but does not itself
produce an error.

Sensitive matching:

- `defaultSensitivePaths` contains `.git`, `.env*`, `id_rsa*`,
  `id_ed25519*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, and a list of config files
  such as `go.mod`, `package.json`, `Makefile`, `Dockerfile`, `pyproject.toml`.
- Policy `sensitive_paths` are merged with the defaults; defaults cannot be
  removed.
- `isSensitivePathParts` checks every path component and the
  basename, normalizes both slash directions, and strips invisible characters
  before matching.
- Protected agent-instruction, credential and persistence targets are a separate
  table: `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Cursor/Windsurf
  rules, `.claude`, `.codex`, `.gemini`, `.continue`, MCP/editor config, CI
  workflows, `.ssh`, `.gitconfig`/`.git/config`, shell startup, fish, desktop
  autostart, `.npmrc`/`.pypirc`/`.netrc`, cron, launchd, systemd user units,
  Windows Startup, and Guard's state/key directories. `.git` itself, including
  `.git/hooks`, is hard-sensitive and never dialog- or grant-approvable.
- `protectedTargetPathWithDirs` / `protectedCall` also check
  relative names against scratch roots and grant directories, so a symlink inside
  an approved root cannot hide a protected target; the active `--state-dir` is
  resolved at startup and added to the table.

Path comparison uses `canonicalPath`, which makes the path
absolute without cleaning `..` before symlink resolution, then
resolves the longest existing prefix. `inside`
re-resolves the approved root, compares filesystem case sensitivity, rejects
environment/drive-relative/control-character forms, and checks the resolved
target is inside the root. This is a check, not a sandbox; a race between check
and write remains possible.

`scan.egress` hosts are matched textually against policy allow/deny patterns.
DNS is not resolved, redirects are not followed, and the actual connection is
not inspected.

Policy classes are `read`, `write`, `exec`, and `egress`. `write` and `exec` are
both sinks after taint; `egress` gets the additional allowlisted-host shortcut.
Unknown tools default to `exec` (`classFor`). Built-in profiles
 pre-classify common servers and are selected by command/package
token or `--name`; policy entries then override individual tools.

## 9. CLI flags and the code they reach

### 9.1 Common proxy flags

The stdio path defines these in `main`; the HTTP path defines the
same names through `registerGuardFlags` and `runProxyCommand`.

| Flag | Parsed at | What it reaches |
|---|---|---|
| `proxy --listen` | `main.go` | `normalizeListenAddr`; default `127.0.0.1:8080`; empty/`localhost` host becomes `127.0.0.1`; `net.Listen` in `runProxyCommand`. |
| `proxy --upstream` | `main.go` | URL validation, `resolveUpstream`, `http.Client` request (`doUpstream`), redacted audit field. Auth headers from the client are copied by `copyRequestHeaders`. |
| `--name` | `main.go` | `nameExplicit`, default from command basename for stdio or `defaultProxyName` for `proxy`, audit filename, policy server lookup, pin filename, clear-taint control hash, `start` audit event. |
| `--state-dir` | `main.go` | Default `~/.sylenix-poc`, `MkdirAll`, audit file, policy autoload, pin file, control/request/result files. |
| `--policy` | `main.go` | `loadPolicyForRun`, strict parse, validation, `applyPolicy`, deprecation notes. Explicit path wins over `<state-dir>/policy.yaml`. |
| `--policy-pubkey` | `main.go` | `loadGuardSigningKeys`, policy verification in `loadPolicyForRun`, pin verification in `loadPins`, audit/start event does not log the key path. |
| `--policy-key` | `main.go` | `loadGuardSigningKeys`, pin signing in `savePins`, and policy verification with the derived public key. Never logged. |
| `--readonly` | `main.go` | `applyPolicy` sets `readonly` and `readonlyOverride`; `classFor` returns `read`; `fromHost` forwards read-class calls before hard blocks. Replaces policy/profile read entries when explicitly set. |
| `--trust` | `main.go` | `applyPolicy`; `fromServer` skips taint and datamarking for trusted `tools/call` results. Replaces policy trust entries when explicitly set. |
| `--approve` | `main.go` | Validated when explicitly set; `applyPolicy`; protected-target handling; dialog branch; `askHuman`; default deny. |
| `--no-spotlight` | `main.go` | `applyPolicy` sets `spotlight`; `fromServer` skips `datamark` for tool results; `datamark`. Note this also skips invisible-character stripping, not only the wrapper. |
| `--reset-pins` | `main.go` | `loadPins` removes the pin file and its signature, logs `pins_reset`, then repins on the next `tools/list`. |
| `--allow-write-under` | `main.go` | Repeatable `stringList`; parsed into `scratchRule`, canonicalized at startup; `applyPolicy`; scratch branch; `scratchAllows`; `protectedCall` checks relative names; `start` event logs the raw specs. |
| `--grant` | `main.go` | Repeatable `stringList`; parsed into seeded non-protected grants; stored in `Guard.grants`; `grantAllows`; protected calls ignore them; dialog grant recording stores exact files for protected targets. |

### 9.2 Subcommand flags

| Command | Flag | Parsed at | What it reaches |
|---|---|---|---|
| `install` | `--yes` | `main.go` | Skips confirmation before config/policy writes. |
| `install` | `--dry-run` | `main.go` | Shows config diff without writing; skips policy/allowlist update. |
| `install` | `--policy` | `main.go` | `policyWritePath` / `writePolicyFile`, and pinned into the wrapper. |
| `install` | `--state-dir` | `main.go` | Default policy location and pinned into the wrapper. |
| `uninstall` | `--yes`, `--dry-run` | `main.go` | Same `runConfigCommand` path, `action == "uninstall"`. |
| `allow` | `--policy` | `main.go` | `policyWritePath`, `loadPolicyForUpdate`, `writePolicyFile`. |
| `allow` | `--state-dir` | `main.go` | Default policy location. |
| `allow` | `--yes` | `main.go` | Skips the confirmation prompt. |
| `version`, `--version`, `-version` | none | `main.go` | Prints `sylenix-guard <version> (<commit>, <go version>)` and exits 0 before flag parsing or server launch. |
| `policy` | none | `main.go` | Positional `validate <file>`, `sign`, `verify` or `print-default`. |
| `keys` | `init --out`, `--key`, `--force`, `--state-dir` | `main.go` | Generates the Ed25519 keypair; refuses a private key inside the state dir; warns that the private key can loosen Guard. |
| `pins` | `sign/verify --name`, `--state-dir`, `--key`, `--pubkey` | `main.go` | Signs or verifies `pins-<name>.json` with a detached `.sig`. |
| `doctor` | `--json` | `main.go` | JSON report instead of human text. |
| `doctor` | `--policy` | `main.go` | Explicit policy for the audit. |
| `doctor` | `--state-dir` | `main.go` | Default state dir when a wrapper does not pin one. |
| `doctor` | `--require-signatures` | `main.go` | Reports unverified policy/pins as findings. |
| `clear-taint` | `--name` | `main.go` | Session name; required; control lookup. |
| `clear-taint` | `--state-dir` | `main.go` | State dir, default `~/.sylenix-poc`. |
| `stats` | `--name` | `main.go` | Reads `<state-dir>/audit-<name>.jsonl`. |
| `stats` | `--file` | `main.go` | Reads the named audit log directly. |
| `stats` | `--state-dir` | `main.go` | Only valid with `--name`. |

Flag/policy precedence in `applyPolicy`: `--approve` overrides
`approval`, `--no-spotlight` overrides `spotlight`, `--readonly` replaces policy
and profile read classes, `--trust` replaces policy trust, and
`--allow-write-under` replaces policy `allow_paths`. `--grant` is flag-only.

## 10. State on disk

Default state directory: `~/.sylenix-poc`. It is created with
`0700`, but an existing directory is not chmod-ed.

| File | Format | Mode | Lifecycle / code |
|---|---|---|---|
| `audit-<name>.jsonl` | One JSON object per line. Base fields: `ts` (RFC3339Nano UTC), `server`, `event`; event-specific fields include `tool`, `rule`, `arg_keys`, `origin`, `class`, `granted`, `scope`, `source`, `version`, `profile`, `command`. Never argument values. | `0600` on create | Opened append-only at startup; written by `event`; no rotation or fsync. |
| `pins-<name>.json` | Indented JSON object: tool name -> 64-character hex SHA-256 of the JSON-marshaled tool definition. | `0600` | `pinsPath`; `loadPins`; `savePins`; atomic temp+rename. |
| `pins-<name>.json.sig` | Raw 64-byte Ed25519 signature over the exact pin-file bytes. | `0600` | Written by `savePins` when `--policy-key` is set; verified by `loadPins` when a public key is configured; removed by `--reset-pins`. |
| `policy.yaml` | Version-1 YAML (strict subset) or JSON. Schema: version, profile, approval, spotlight, sensitive_paths, egress allow/deny hosts, allowlist, servers/tools. | `0600` when written by Guard | Auto-loaded from state dir or `--policy`; strict parse/validation; canonical write drops comments and stale signatures. |
| `policy.yaml.sig` | Raw 64-byte Ed25519 signature over the exact policy bytes. | `0600` | Written by `policy sign`; verified at startup; removed by `install`/`allow` rewrites. |
| `~/.sylenix-keys/policy-signing.key` | PKCS#8 PEM Ed25519 private key. | `0600` | `keys init` default path, outside the state dir; never read by `doctor`. |
| `~/.sylenix-keys/policy-signing.key.pub` | PKIX PEM Ed25519 public key. | `0600` | Written by `keys init`; pass with `--policy-pubkey`. |
| `control-<hash>.json` | JSON `{version,name,pid,nonce,started_at,heartbeat}`. `<hash>` is the first 16 bytes of SHA-256(name), hex. | `0600` | Created by `startGuardControl`; heartbeat every 2 s; stale after 15 s; removed on exit. |
| `clear-taint-request-<hash>.json` | JSON `{version,nonce,guard_started,request_id,requested_at}`. | `0600` | Written by CLI; polled and removed by guard; TTL 2 min. |
| `clear-taint-result-<hash>-<request_id>.json` | JSON `{version,request_id,status,who,at,note}`. | `0600` | Written by guard; read and removed by CLI; stale results removed at next guard start. |
| `<config>.sylenix-backup-<UTC timestamp>` | Byte-for-byte copy of an MCP client config before `install`/`uninstall`. | Original file mode | `writeConfigBackup`. |
| `policy.yaml` written by `install`/`allow` | Canonical YAML; comments/formatting not preserved. | `0600` | `writePolicyFile`. |

No tokens or auth headers are stored. The HTTP proxy keeps only the configured
upstream URL and an in-memory HTTP client; `Mcp-Session-Id` is passed through and
never written to disk. The audit log records tool names, argument key names,
paths/scope values, and command paths, but not argument values or header values
(`event`; also `POC_SPIKE.md`).

## 11. What `make check` runs

`make check` is the aggregate target `check` in `Makefile`:

```text
check: fmt spdx-check vet selftest probe-test proxy-test signing-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test team-test
```

It runs, in order:

1. **`fmt`** (`Makefile`): fails if `gofmt -l cmd teams demo` reports any file.
2. **`spdx-check`** (`Makefile`): fails if any `.go` or `.py` file under `cmd`,
   `teams`, `demo`, `scripts` or `tests` lacks
   `SPDX-License-Identifier: Apache-2.0`.
3. **`vet`** (`Makefile`): `CGO_ENABLED=0 go vet ./...`.
4. **`selftest`** (`Makefile`): builds the binary, then runs
   `python3 demo/selftest.py` and `python3 demo/selftest.py --policy`.
5. **`probe-test`** (`Makefile`): builds and runs the regression probes:
   `test_scratch_grant_bypass.py`, `test_protected_targets.py`,
   `test_policy.py`, `test_allowlist.py`, `test_install.py`,
   `test_version.py`.
6. **`proxy-test`** (`Makefile`): `tests/probes/test_http_proxy.py`, the
   stdio/HTTP parity, SSE, session, auth-header and pin-quarantine probes.
7. **`signing-test`** (`Makefile`): `tests/probes/test_signing.py`, key
   generation, policy/pin signing, tamper detection and unsigned-file rejection.
8. **`profile-test`** (`Makefile`): `test_profiles.py` for the built-in
   filesystem, git, GitHub, fetch, shell, Slack, Postgres, browser, Notion, and
   Jira profiles.
9. **`replay-test`** (`Makefile`): `scripts/replay_profile_session.py`,
   which reports approval prompts per active hour for the recorded filesystem
   session.
10. **`summary-test`** (`Makefile`): runs `scripts/summarize_audit.py` on
    `demo/fixtures/audit_sample.jsonl`, strips CRs with `tr`, and diffs against
    `demo/fixtures/audit_sample.expected.txt`.
11. **`doctor-test`** (`Makefile`): `tests/probes/test_doctor.py`.
12. **`clear-taint-test`** (`Makefile`):
    `tests/probes/test_clear_taint.py`.
13. **`stats-test`** (`Makefile`): `tests/probes/test_stats.py`.
14. **`team-test`** (`Makefile`): builds both binaries and runs
    `CGO_ENABLED=0 go test ./teams/... -count=1` for `teams/auditevent`,
    `teams/auditshipper` and `teams/policyserver`.

`team-test` sets `CGO_ENABLED=0` so the test binaries use Go's internal linker.
That avoids the dyld `missing LC_UUID` failure seen when those binaries are
externally linked by cgo on newer macOS SDKs.

CI also runs `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` as a
separate gate before `make check`.

`make check` does not run the agent harness, sweep, or the `gif` target.
`make harness-scripted` (`Makefile`) uses
`.venv/bin/python demo/harness.py --agent scripted --runs 3`; that path is
Unix-style and does not work as written on Windows. `make gif` builds
`bin/gifrunner` and runs `vhs demo/quickstart.tape`.

On Windows, `make check` needs a POSIX shell because `fmt` uses `test`, and
`summary-test` uses `tr` and `diff` (`README.md`).

## 12. What `demo/selftest.py` checks

`demo/selftest.py` is a dependency-free protocol test. It starts a fresh guard
per case in front of `demo/fake_server.py`, so each case begins with a clean
taint state. It runs twice under `make check`: flags mode and `--policy` mode.
The policy mode writes an equivalent state-dir policy with
`read_ticket: class: read` instead of passing `--readonly read_ticket`. It uses
`bin/sylenix-guard` or `bin/sylenix-guard.exe` and its test handshake uses
protocol version `2025-06-18`.

The cases, in execution order:

| Case | What it checks |
|---|---|
| `case_taint_flow` | Clean write allowed; a read result is datamarked, closing-tag payload neutralized, zero-width characters stripped; after taint a write and an unmapped tool are blocked with `TAINT_SINK`; read-only still works; blocked calls do not reach the server; clean exit. |
| `case_pin_persistence` | First `tools/list` writes `pins-t.json`; a changed definition on restart is quarantined with `-32001`; audit records the quarantine and contains no `"arguments"` string. |
| `case_invisible` | Nineteen invisible code points in a tool definition each cause quarantine; ordinary accents, CJK, and emoji do not. |
| `case_noisy` | A non-JSON server line is forwarded unchanged and taints the session. |
| `case_bad_input` | Garbage gets `-32700` with id null; a batch gets `-32600`; the session survives. |
| `case_large_frame` | A 3 MiB trusted result arrives intact. |
| `case_interleaving` | 300 blocked calls plus 300 forwarded pings produce 600 valid JSON replies, checking stdout serialization. |
| `case_duplicate_keys` | Duplicate keys in a host frame are refused with `DUPLICATE_KEYS` and id null; duplicate keys in sibling objects are not false positives; refused frame never reaches server. |
| `case_unmatched_response` | A response to an unknown id is forwarded and taints. |
| `case_oversize_frames` | Exactly 10 MiB accepted; one byte over refused with `FRAME_TOO_LARGE`; session survives; oversize server frame fails pending requests with `SERVER_FRAME_TOO_LARGE` and taints. |
| `case_server_stream_closed` | Pending and later requests fail with `SERVER_STREAM_CLOSED`; guard exits within 10 s with code 1. |
| `case_duplicate_ids` | A second request with a still-pending id is refused with `DUPLICATE_ID` and id null; first request keeps its identity; ids can be reused after completion. |
| `case_pin_file_damage` | Invalid JSON, null, list, empty file, null value, non-hash, and empty name all make the guard exit 2 without launching the server; `--reset-pins` recovers and logs `pins_reset`. |
| `case_structured_content` | Invisible characters are stripped from `structuredContent` strings; numbers are preserved exactly; text content is still datamarked. |
| `case_server_request_taint` | A sampling request is forwarded; a trusted tool result does not taint by itself; server-request content latches `TAINT_SERVER_REQUEST`; egress is then blocked; audit records the rule but not the sampling marker. |
| `case_scratch_writes` | Writes inside `--allow-write-under` pass; outside and `..` escapes are blocked; `.env`, `.git`, and root config names are `SENSITIVE_TARGET`; URL arguments are `EGRESS_TARGET`; URLs inside content are not; `TOOL=DIR` scopes the fast path; only allowed writes reach the server. |
| `case_grants` | Live grant allows; scoped grant does not cover outside paths; expired grant stops allowing; tool-wide grant covers any path; grants never cover egress or sensitive paths; malformed grant/scratch specs exit 2. |
| `case_dialog_fails_closed` | On Linux without `zenity`, a dialog-mode blocked call returns `-32002`; on platforms with a real dialog the case is skipped to avoid showing one. |

`tests/probes/test_http_proxy.py` is the transport-specific companion. It starts
`tests/probes/http_fake_server.py`, a minimal Streamable HTTP MCP server, and
runs the same taint/block sequence through the stdio and HTTP proxies. It also
covers POST SSE responses, server notifications on POST and GET SSE, session
IDs, auth-header pass-through, token non-persistence in state files, and pin
quarantine across a restart. The fake upstream requires `Authorization` and a
valid `Mcp-Session-Id` after initialization, so a proxy that drops either one
fails the probe.

`tests/probes/test_signing.py` covers `keys init`, policy sign/verify, automatic
pin signing, one-byte policy and pin tamper detection, unsigned-file rejection,
`pins sign` recovery, and the public-key-only team mode. It also checks that
`keys init` refuses a private key inside the state directory.

## 13. Risky or unclear areas

These are observations about the current code, not changes. Some are deliberate
scope limits; some are worth fixing.

### Scope and architecture

1. **Proxy mode is one Streamable HTTP endpoint, not a general HTTP gateway.**
   It covers one remote MCP server per process, uses the 2025-11-25
   POST/GET/DELETE/session model, and tolerates the stateless 2026-07-28 shape.
   The legacy HTTP+SSE transport from 2024-11-05 is not implemented. There is no
   multi-server routing, OAuth broker, token refresh, or credential store; the
   client's auth headers are passed through (`copyRequestHeaders`,
   `main.go`) and never logged or persisted.
2. **Taint is per guard process and per wrapped server.** It does not cover
   host built-in tools, attachments, or pasted text, and restarting the guard
   starts a clean session (`POC_SPIKE.md`; `main.go`). This is
   fundamental to the current design.
3. **No confidentiality latch.** Reading a secret and then calling a read-only
   tool is not tracked (`POC_SPIKE.md`).
4. **The HTTP proxy does not enforce the server-command allowlist.** The
   allowlist is a launch control for a child process (`checkServerAllowed`,
   `main.go`); `proxy` has no child command and skips it. A policy with
   `allowlist_enforced: true` therefore does not restrict `--upstream`.
5. **SSE resumability is left to the client and upstream.** The proxy forwards
   `Last-Event-ID` and SSE event IDs, but keeps no replay buffer and does not
   persist streams (`copyRequestHeaders`, `main.go`; `streamSSE`). A broken
   connection loses in-flight events unless the upstream can replay them. This
   matches the 2026-07-28 direction, which removes resumability, but is a real
   gap for 2025-11-25 servers that expect the client to resume.
6. **Auth-header pass-through is broad by design.** Every end-to-end request
   header except the explicit hop-by-hop/Host/Content-Length/Origin set is
   copied upstream (`copyRequestHeaders`, `main.go`). That includes
   `Authorization`, `Cookie`, `X-Api-Key` and any custom auth header the client
   sends. The guard does not validate the credential, scope it to a host, or
   replace it. Only the configured `--upstream` sees it.
7. **The HTTP listener is loopback-only by default, but `--listen` can expose
   it.** `normalizeListenAddr` maps an empty host or `localhost` to
   `127.0.0.1` (`main.go`), but an explicit `0.0.0.0` or LAN address is
   accepted. The listener itself is plain HTTP; use a loopback address or a
   trusted tunnel/reverse proxy for anything else. Origin and Host checking are
   not a substitute for authentication (`originAllowed`, `hostHeaderAllowed`).
8. **Session IDs are passed through, not mapped per client.** A client that
   presents another client's `Mcp-Session-Id` is forwarded with that ID; the
   proxy adds no session isolation of its own (`copyRequestHeaders`,
   `main.go`). The upstream is responsible for authenticating the
   session, as it would be without the proxy.

### Enforcement gaps that are easy to trip over

9. **`--readonly` / `class: read` bypasses every sink check, including
   `EGRESS_TARGET` and `SENSITIVE_TARGET`.** The read check is before the hard
   blocks (`main.go`), and `classFor` returns `read` for anything on
   the list. `POC_SPIKE.md` calls this a trust decision. A
   mis-listed tool defeats the latch.
10. **`--trust` suppresses taint and datamarking for that tool's results.**
   `fromServer` returns early for trusted `tools/call` results (`main.go`).
   Trust only applies to `tools/call`, not `resources/read` or `prompts/get`.
11. **`--no-spotlight` disables more than the wrapper.** It skips the entire
   `datamark` call (`main.go`), so invisible-character stripping and
   `structuredContent` cleanup are skipped too. The flag help says only "do not
   datamark", and `POC_SPIKE.md` says "Skip datamarking".
12. **Argument classification is a heuristic.** Only known path keys are treated
   as paths; a path under a content-named key is ignored (`main.go`),
   and an unknown-shaped value can be classified as ambiguous or not path-like
   at all (`looksLikePath`). A tool-wide `--grant`
   can therefore cover calls whose path the guard did not recognize. This is
   acknowledged in `POC_SPIKE.md`.
13. **Pinning is trust on first use and does not sanitize the first
   definition.** A first `tools/list` can contain prompt-injected tool
   descriptions; the guard pins them rather than rejecting them
   (`main.go`, `POC_SPIKE.md`). Pin files are signed only when
   `--policy-key`/`--policy-pubkey` enables signing; otherwise they remain
   same-user writable, and signing detects modification rather than rollback.
14. **A later identical `tools/list` un-quarantines a tool.** `inspectToolsList`
   deletes the quarantine entry when the definition matches the old pin
   (`main.go`). That is probably intended recovery, but it means a server
   that alternates between two definitions moves the tool in and out of
   quarantine; calls are blocked only during the quarantined period.
15. **`tools/list` pinning is skipped silently if the result shape is not the
    expected `{tools: [...]}`.** `inspectToolsList` returns without error on
    unmarshal failure (`main.go`), so no pins and no quarantine are
    recorded for that response.
16. **The guard does not reject duplicate keys in server frames.** Host frames
    get the `hasDuplicateKeys` check (`main.go`), but `fromServer`
    decodes with plain `json.Unmarshal` and never checks duplicates.
    A malicious server can present one value to the guard and another to a
    host whose JSON parser resolves duplicates differently. The same issue
    exists inside tool definitions and policy JSON only insofar as the guard
    decodes them.
17. **Datamarking is structural, not a real content boundary.** It only wraps
    `content[].text` and only neutralizes the exact lower-case
    `</untrusted_tool_result` string (`main.go`). Case variants, unusual
    result shapes, resource/prompt results, and non-text content are not
    wrapped. `POC_SPIKE.md` acknowledges that
    spotlighting is friction, not protection.

### Path, egress, and approval risks

18. **Sensitive/egress checks are textual and path-based, not a sandbox.**
    Egress matching compares host strings and does not resolve DNS, follow
    redirects, or pin IPs (`main.go`, `POC_SPIKE.md`). Scratch
    path checks resolve symlinks but leave a check-to-write race
    (`main.go`, `POC_SPIKE.md`).
19. **A grant is broader than one call, but protected grants are exact-file.**
    `addGrant` records the tool and either the exact canonical files (protected
    targets) or a directory (non-protected calls). `grantAllows` matches exact
    files for a protected grant and directory membership for a non-protected
    grant, for 15 minutes (`main.go`). A human approval for one protected file
    does not cover another protected file. `POC_SPIKE.md` documents the scope.
20. **Dialog mode blocks the calling transport while a dialog is open.**
    `askHuman` runs synchronously in the stdio host-to-server goroutine
    (`main.go`; `POC_SPIKE.md`). In stdio mode that
    stalls the whole session; in HTTP mode only that request's handler waits,
    but concurrent requests can each open a dialog. A slow or stuck dialog
    stalls the call for up to 60 seconds.
21. **Dialog text is truncated and sanitized, not a trustworthy rendering of
    the call.** Arguments are cut at 300 characters and control/invisible
    characters are removed (`cleanForDialog`; `askHuman`). Confusable or long
    arguments can still mislead a human.

### State, audit, and local-process risks

22. **`--name` is validated at startup, but `stats --name` still concatenates
    an unvalidated name.** `prepareGuard` now uses `validDoctorName`
    (`main.go`), so the proxy and stdio paths reject path
    separators. `stats --name` still builds `audit-<name>.jsonl` directly, so a
    caller can read another `.jsonl` path relative to the state directory. Use a
    simple name and a unique state directory.
23. **Audit and pin write errors are ignored.** `event` discards the
    `log.Write` result (`main.go`), and `savePins` discards both the
    temp-file and rename errors. A full or read-only state
    directory can silently lose audit records or pins while the proxy keeps
    running. There is no fsync or rotation.
24. **Existing state-dir and audit-file permissions are not tightened.**
    `MkdirAll(..., 0700)` and `OpenFile(..., 0600)` only set modes on creation
    (`main.go`); an existing `0755` directory or `0644` audit file stays
    that way.
25. **Clear-taint control files are same-user state, not authentication.**
    A same-user process, including the wrapped server, can request a dialog
    (`main.go`; `POC_SPIKE.md`). Only a human click clears the
    latch, but the dialog is local and not biometric. A successful clear does
    not revoke grants or quarantines.
26. **Two guards using the same `--name` and state dir share pins, audit, and
    control paths.** The control path is keyed by a hash of the name
    (`main.go`), and `cleanupStaleFiles` removes request/result files
    for that name at startup. Use a unique name per guard;
    `POC_SPIKE.md` makes the same point for clear-taint.
27. **`install` and `allow` persist and print server arguments.** The allowlist
    is an exact command/args record (`main.go`), and
    `allow`/`install` print the arguments to the terminal
     before writing them to `policy.yaml`. If a
    server passes a token in an argument, it can end up in the policy file and
    terminal scrollback. The audit log itself does not record argument values.
28. **The server's stderr is inherited, not mediated.** `cmd.Stderr = os.Stderr`
    (`main.go`) means a server can write directly to the operator's terminal,
    including escape sequences or secrets, without the guard inspecting it.
29. **The pending-request map never expires.** `track` adds ids and only
    `take`/`failPending` remove them (`main.go`); a server that never
    answers an id leaves an entry for the life of the process
    (`POC_SPIKE.md`).
30. **Signal cleanup is minimal.** The signal goroutine stops control, kills the
    child, and exits (`main.go`); descendants of a wrapper such as
    `npx` are not killed (`POC_SPIKE.md`).

### Build, test, and configuration clarity

31. **`make check` is POSIX-shell dependent on Windows.** `fmt` uses `test`
    (`Makefile`), and `summary-test` uses `tr` and `diff`
    (`Makefile`); `README.md` says Git Bash or WSL is required.
    `make harness-scripted` also hard-codes `.venv/bin/python`
    (`Makefile`), which is not a Windows path.
32. **Core proxy coverage is probe-based, not Go unit-tested.** `make check`
    runs `go vet`, the Python protocol/probe suites, and
    `CGO_ENABLED=0 go test ./teams/...` for the paid-tier packages, but the core
    `cmd/sylenix-guard` package has no Go unit tests. A regression in an
    unexercised core helper can pass the suite.
33. **Policy loading is one-shot; signing is optional.** The file is read at
    startup and not watched (`main.go`; `POC_SPIKE.md`). When a
    public key is configured, the exact bytes must have a valid `.sig` or the
    guard exits 2 before parsing (`loadPolicyForRun`). Without
    `--policy-pubkey`/`--policy-key`, an unsigned policy is still accepted. A
    policy file with several `servers` entries must contain the active `--name`.
34. **`--policy` / policy precedence can surprise.** `--readonly` replaces both
    policy and profile read classes, `--trust` replaces policy trust, and
    `--allow-write-under` replaces all policy `allow_paths` (`main.go`).
    This is documented but easy to miss; a flag intended as an addition can
    silently remove profile defaults.
35. **Allowlist enforcement can be explicitly disabled with
    `allowlist_enforced: false` even when entries exist.** `applyPolicy` honors
    an explicit false (`main.go`). `docs/POLICY.md` only
    describes the omitted-field behavior; the explicit-false-with-entries case
    is easy to misread.
36. **The signing private key is only as protected as the local account.**
    `keys init` writes it outside the state directory with mode `0600`, but a
    same-user process can still read it and sign a replacement policy or pin
    store (`runKeysCommand`). There is no HSM, OS keystore, remote
    signer or key passphrase.
37. **Signing does not detect rollback.** An attacker with file access can
    restore an older signed policy/pin pair; there is no monotonic counter,
    transparency log or revocation list (`verifyDetachedSignature`). Treat
    signatures as tamper evidence, not freshness.
38. **Deleting a signature is a denial of service, not a bypass.** A missing
    `.sig` or a truncated signature stops startup with exit 2
    (`loadPolicyForRun`; `loadPins`). Keep backups of
    the policy, pin store, signatures and public key.
