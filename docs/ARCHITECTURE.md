# Sylenix Guard Architecture

This document maps the code as it exists today. It is descriptive, not a
roadmap. The source of truth for scope is `POC_SPIKE.md`; the full product
intent is in `docs/SPEC_FULL.md`.

## 1. Shape of the system

Sylenix Guard is one Go binary (`cmd/sylenix-guard/main.go`, package `main`,
standard library only). It supports two transports for exactly one MCP server
per process:

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
(`demo/selftest.py:95`); the HTTP probes use `2025-11-25`.

The same binary also contains the non-proxy subcommands: `install`, `uninstall`,
`policy`, `allow`, `doctor`, `clear-taint`, and `stats`. `main` dispatches those
before parsing proxy flags (`:215-234`).

### 1.1 Streamable HTTP proxy mode

`proxy` is a separate transport front end over the same `Guard` decision core:

- `--listen` defaults to `127.0.0.1:8080`; an empty host or `localhost` is
  normalized to `127.0.0.1` (`normalizeListenAddr`, `:721-741`).
- `--upstream` is required and must be an absolute `http` or `https` URL
  (`:621-637`). Its query string is forwarded to the upstream but redacted from
  logs and audit events (`redactURL`, `:763-772`).
- `POST` carries one JSON-RPC message. `GET` opens the optional server-to-client
  SSE stream. `DELETE` terminates the upstream session. `OPTIONS` answers
  locally (`ServeHTTP`, `:790-809`).
- `Origin` is checked before any request is forwarded. Missing Origin is
  allowed; loopback origins and the request host are allowed; anything else
  gets HTTP 403 (`originAllowed`, `:811-832`).
- Request headers are copied end to end except hop-by-hop headers, `Host`,
  `Content-Length`, `Accept-Encoding`, and `Origin` (`copyRequestHeaders`,
  `:1031-1041`). `Authorization`, `Cookie`, `Mcp-Session-Id`,
  `MCP-Protocol-Version`, and `Last-Event-ID` therefore reach the upstream.
  Header values are never logged.
- `Mcp-Session-Id` is passed through in both directions. The proxy does not
  mint, store, or persist session IDs. This is valid for the session-bearing
  MCP 2025-11-25 revision; it also works with the stateless 2026-07-28 shape
  because the header is simply absent.
- Upstream `content-type: application/json` bodies are inspected by
  `fromServer` and returned as JSON. `text/event-stream` bodies are parsed event
  by event, inspected by `fromServer`, and re-emitted as SSE (`streamSSE`,
  `:1101-1184`). SSE comments, `event:`, `id:`, `retry:` and multi-line `data:`
  fields are preserved.
- A blocked host message returns a JSON-RPC error immediately without contacting
  the upstream (`handlePost`, `:834-915`). A notification that the guard drops
  gets HTTP 202.
- Upstream failures and oversized frames fail the pending request with
  `UPSTREAM_ERROR`, `SERVER_FRAME_TOO_LARGE`, or `SERVER_STREAM_CLOSED` rather
  than leaving the client waiting (`failOne`, `:5328-5334`; `finishPending`,
  `:1222-1230`).

The legacy HTTP+SSE transport from 2024-11-05 (separate SSE and POST endpoints)
is not implemented. `install` still skips remote config entries
(`:1912-1953`, `:8020-8037`), and `doctor` reports them as
`REMOTE_NOT_COVERED` (`:6551-6553`) because installing a remote transport is a
client-configuration decision, not a wrapper decision; the finding now points at
manual `proxy` configuration.

## 2. Entry point and startup sequence

`main()` is at `cmd/sylenix-guard/main.go:215`.

1. Subcommand dispatch (`:216-232`). If `os.Args[1]` is a known subcommand, run
   it and exit. Otherwise fall through to proxy mode.
2. Proxy flag parsing (`:236-248`). `flag.Visit` records which flags were
   explicitly supplied (`:250-251`), so flags can override policy only when the
   operator actually set them.
3. Input validation and flag expansion:
   - `--approve` must be `deny` or `dialog` when explicitly set (`:422-425`).
   - `--allow-write-under` becomes `[]scratchRule`, with `TOOL=DIR` support
     (`:427-441`).
   - `--grant` becomes seeded in-memory grants, with `TOOL[:DIR]=DURATION`
     parsing (`:442-465`).
4. Name and state-directory defaults (`:466-486`). The default name is the
   server command's basename; the default state directory is `~/.sylenix-poc`.
5. State directory creation with mode `0700` and audit-log open with mode
   `0600` (`:486-491`).
6. `Guard` construction (`:494-505`).
7. Policy resolution and application (`:506-523`): explicit `--policy`, else
   `<state-dir>/policy.yaml`, else built-in defaults; profile selection; flag
   overrides.
8. Server allowlist check before the child is launched (`:276-285`). A refusal
   exits `2` and writes `SERVER_NOT_ALLOWED` to the audit log.
9. Pin-file load; an unreadable pin file exits `2` unless `--reset-pins`
   (`:286-289`).
10. Child process start with stdin/stdout pipes; stderr is inherited
    (`:291-306`).
11. Start event and clear-taint control loop (`:307-315`).
12. Signal handler (`:317-324`), then two long-lived goroutines: host-to-server
    (`:335-367`) and server-to-host (`:369-400`).
13. Wait for the server-to-host loop and the child, stop the control loop, log
    the exit, and exit with the child's code (`:401-411`).

The child is killed five seconds after either side closes its input, on a
signal, or when the guard shuts down (`:326-333`, `:317-324`, `:394-398`).

Proxy mode shares steps 3 through 9 through `prepareGuard` (`:417-527`). It then
binds the listener (`runProxyCommand`, `:591-719`), starts the same clear-taint
control loop, emits a `start` event with `transport: streamable-http`, and serves
HTTP until a signal or listener error. It does not check the server-command
allowlist because there is no child command to launch; the stdio allowlist
remains a launch-only control.

## 3. Main data structures

All in `cmd/sylenix-guard/main.go`:

| Type | Purpose | Location |
|---|---|---|
| `Guard` | Entire per-process state: policy, taint, pending requests, pins, quarantines, grants, output writer, audit writer | `:159-196` |
| `guardOptions` | Shared startup configuration for stdio and HTTP | `:200-213` |
| `frame` | `map[string]json.RawMessage` for one JSON-RPC object | `:121` |
| `pendingReq` | Tracks the method and tool name for an outstanding request id | `:123-126` |
| `scratchRule` | One `--allow-write-under` entry: optional tool plus directory | `:130-133` |
| `grant` | One time-bounded approval: tool, optional directory, expiry, human/protected flags | `:137-143` |
| `policyFile` | Strict on-disk policy schema | `:74-84` |
| `policyTool` | Per-tool class, extra path keys, allow paths, trust | `:105-110` |
| `policyProfile` | Built-in classification table for a known server family | `:114-119` |
| `guardFlagValues` | Common proxy flags registered by both dispatch paths | `:531-554` |
| `sseEvent` | One parsed server-sent event | `:557-567` |
| `proxyHandler` | HTTP transport state: Guard, upstream URL, HTTP client | `:569-573` |
| `guardControl` | Clear-taint control-file implementation | `:5449-5461` |
| `controlFile`, `clearRequest`, `clearResult` | On-disk control/request/result JSON shapes | `:5423-5447` |

Concurrency boundaries:

- `Guard.mu` protects taint state, `pending`, `pins`, `quarantined`, and
  `grants` (`:181-187`). Policy maps are built before the goroutines start and
  are read-only afterwards.
- `Guard.outMu` serializes every write to the host's stdout (`:191`, `:5345-5354`).
  Proxy mode points `out` at `io.Discard`; responses go through the HTTP handler.
- `Guard.logMu` serializes audit-log writes (`:194`, `:5358-5367`).
- `serverGone` is an `atomic.Bool` set when the server's stdout closes (`:189`,
  `:395`).

## 4. Request path: host -> Guard -> server

In stdio mode the host reader is `readFrame` (`:5255-5279`), called in the host goroutine
(`:335-367`). It enforces the 10 MiB frame limit (`:46`) and a 64 MiB discard
budget (`:47`, `:5271-5273`). Oversize host frames are answered with `-32600
FRAME_TOO_LARGE` and id `null`; the connection survives unless the line cannot
be framed (`:346-353`).

In HTTP mode the POST body is bounded by the same `maxFrame` and passed to the
same `fromHost` (`handlePost`, `:834-915`). The explicit-allow branch then sends
the original body to the upstream. Blocked requests get a JSON-RPC error body
with HTTP 200; notifications get HTTP 202. The HTTP transport never calls
`Guard.write`, so the stdio writer is not involved.

`Guard.fromHost` (`:3443-3583`) decides every host frame:

1. **Batch frames** (`:3445-3448`): top-level `[` is refused with `-32600
   BATCH_UNSUPPORTED`; not forwarded.
2. **Malformed JSON** (`:3449-3453`): `-32700 UNPARSEABLE`, id `null`; not
   forwarded.
3. **Duplicate keys anywhere in the JSON object** (`:3454-3457`): `-32600
   DUPLICATE_KEYS`, id `null`; not forwarded. This is a deliberate parser
   differential defense.
4. **Host responses to server requests** (`:3458-3463`): a frame with no
   `method` is forwarded as a response without further inspection.
5. **Server already gone** (`:3464-3466`): requests get `-32000
   SERVER_STREAM_CLOSED`; notifications get no reply.
6. **Duplicate pending id** (`:3467-3472`): `-32600 DUPLICATE_ID`, id `null`;
   the first request keeps its identity.
7. **Non-`tools/call` methods** (`:3473-3476`): tracked by id, then forwarded.
8. **`tools/call` parsing** (`:3478-3485`): missing or non-object `params`, or
   an empty tool name, gets `-32000 UNPARSEABLE_CALL`.
9. **Quarantine** (`:3487-3496`): a quarantined tool is blocked with `-32001
   MANIFEST_QUARANTINE`, even in a clean session.
10. **Clean session or read-class tool** (`:3497-3502`): forwarded. The class is
    `read` if the tool is in `--readonly`, a profile read default, or policy
    `class: read` (`classFor`, `:4343-4351`). This check is before every hard
    block.
11. **Tainted non-read call** (`:3504-3582`) is decided in this order:
    1. **`EGRESS_TARGET`** (`:3508-3522`): any network-shaped argument, unless
       every parsed host is on the policy egress allowlist and none is on the
       denylist. The hard block is not dialog-approvable and is not covered by a
       grant or scratch rule.
    2. **`SENSITIVE_TARGET`** (`:3523-3527`): any sensitive path match. Also not
       dialog-approvable, grant-covered, or scratch-covered.
    3. **Protected persistence/agent-instruction target** (`:3528-3535`): if the
       target is protected and approval mode is not `dialog`, block with
       `SENSITIVE_TARGET`. With `--approve dialog`, it can reach a human.
    4. **Egress allowlist shortcut** (`:3536-3550`): an `egress`-class tool whose
       every destination is allowlisted can run without a prompt, unless the
       call is ambiguous or protected.
    5. **Live grant** (`:3551-3560`, `grantAllows` at `:4866-4890`): a
       time-bounded grant can allow the call only when there is no egress and no
       ambiguity, and every path stays inside the grant's directory (or the
       grant is tool-wide and paths resolve safely). Protected calls require a
       human-recorded protected grant.
    6. **Scratch write** (`:3561-3565`, `scratchAllows` at `:4895-4907`): no
       prompt while every path stays inside an `--allow-write-under` root. No
       recognizable path means no scratch shortcut.
    7. **Dialog** (`:3566-3579`, `askHuman` at `:4914-4965`): with
       `--approve dialog`, offer Deny / Allow Once / Allow Tool for 15m.
       A grant records a directory scope and is held in memory.
    8. **Default deny** (`:3580-3582`): `-32000 TAINT_SINK`.

A blocked request gets an error frame only when it has an id; notifications are
dropped silently (`replyIfRequest`, `:5385-5391`). Error data carries only a rule
name (`errorFrame`, `:5373-5383`).

## 5. Response path: server -> Guard -> host

In stdio mode the server reader is the same `readFrame` logic (`:369-400`).
Oversize server frames cannot be inspected or matched to a request, so the guard
latches taint, fails every pending request with `-32000 SERVER_FRAME_TOO_LARGE`,
and discards the frame (`:382-390`).

In HTTP mode JSON bodies are read with the same limit and passed to `fromServer`
(`handlePost`, `:834-915`). SSE responses are parsed by `streamSSE`
(`:1101-1184`): each `data:` payload is passed to `fromServer`, and the resulting
message is re-emitted with its `event:`/`id:`/`retry:` fields. A stream that ends
without the pending response gets a synthetic `SERVER_STREAM_CLOSED` error event
(`finishPending`, `:1222-1230`).

`Guard.fromServer` (`:3636-3685`) handles a server line:

1. **Unparseable server output** (`:3642-3647`): forwarded unchanged and taints
   with origin `unparseable_server_output`.
2. **Server request or notification** (`:3648-3659`): forwarded so the host can
   answer. If it carries text/resource content, the guard logs only the method
   and rule and latches with reason `TAINT_SERVER_REQUEST`.
   `serverMessageHasContent` is at `:3590-3634`; `sampling/createMessage` and
   `elicitation/create` always count, other methods are inspected against
   content-key names.
3. **Response matching** (`:3661-3666`): the id is removed from `pending`. An
   unmatched response is forwarded unchanged and taints with origin
   `unmatched_response`.
4. **`tools/list`** (`:3667-3670`): `inspectToolsList` pins or quarantines tool
   definitions before the line is forwarded.
5. **`tools/call`, `resources/read`, `prompts/get`** (`:3671-3683`): a
   `tools/call` result for a `--trust`ed tool is forwarded without taint or
   datamarking. Every other such result latches taint *before* the host can see
   it. `tools/call` text results are datamarked when spotlighting is enabled;
   resource and prompt results are not wrapped.
6. **Everything else** is forwarded unchanged.

`datamark` (`:3718-3764`) wraps each `text` content item in
`<untrusted_tool_result origin="..." integrity="untrusted">`, neutralizes the
literal lower-case closing tag, strips invisible characters, and strips
invisible characters from `structuredContent` strings without wrapping the
structured value. If the result shape is not the expected object/content array,
it returns the original line; taint has already been latched.

## 6. Taint lifecycle

Taint is in memory only. It begins clean in each new guard process.

**Set** by `latch` / `latchReason` (`:3687-3707`). The first latch records the
origin and emits `taint_latched`; later latches only set the boolean.

Triggers:

| Trigger | Code |
|---|---|
| Untrusted `tools/call` result | `:3671-3679`; `--trust` bypasses only this branch |
| `resources/read` or `prompts/get` result | `:3671-3679` |
| Unparseable server stdout line | `:3642-3647` |
| Server response whose id matches no pending request | `:3661-3666` |
| Server request/notification carrying content | `:3650-3657`, `:3590-3634` |
| Oversize server frame | `:382-386` (main server loop) |

**Cleared** only by `clearTaint` (`:3711-3716`), which is called only from the
human-approved clear-taint control path (`:5659-5714`). A successful clear emits
`CLEAR_TAINT` with `who`, `method: dialog`, and a request id. It does not revoke
grants, quarantines, or the server process. MCP tool calls, host methods, server
messages, and environment variables cannot clear the latch.

The `clear-taint` CLI (`:5769-5855`) writes a nonce- and guard-start-bound request
file into the state directory and waits for the running guard's result. The
guard polls every 200 ms (`:5571-5583`), validates version, nonce, start time,
request age, and request id (`:5603-5643`), then shows an OS dialog
(`askClearTaint`, `:4970-5011`). Denial, timeout, or an unavailable dialog keeps
the latch.

## 7. Tool pinning and quarantine

On a `tools/list` response, `inspectToolsList` (`:3768-3813`) does the following
for each tool with a non-empty name:

1. Marshal the decoded tool object to JSON. Go sorts map keys, so the encoding
   is stable for the same decoded value (`:3782`).
2. SHA-256 the encoding and hex-encode it.
3. Compare with the pin map (`old, seen := g.pins[name]`, `:3785`).
4. Quarantine if the tool contains invisible characters (`containsInvisible`,
   `:3789-3790`, `:5203-5221`) or if a previously seen definition now has a
   different hash (`:3791-3792`).
5. Otherwise remove any old quarantine for that name, and if this is first
   sight, store the hash and emit `tool_pinned` (`:3802-3807`).

Quarantine is a tool-name map to a reason string. A quarantined tool is blocked
before taint is even considered (`:3492-3496`). If a later `tools/list` returns
the original pinned definition again, the `delete(g.quarantined, name)` at
`:3802` removes the quarantine.

The pin file is `pins-<name>.json` (`:3815`). `loadPins` (`:3819-3849`) treats a
missing file as first use, but refuses to start if the file exists and is
unreadable, is not a JSON object, has an empty tool name, or has a value that is
not a 64-character hex SHA-256. `--reset-pins` deletes the file and logs
`pins_reset` (`:3819-3823`). `savePins` writes indented JSON through a temporary
file and rename (`:3851-3859`).

## 8. EGRESS and SENSITIVE classification

Classification happens only for a tainted, non-read `tools/call`, in
`scanArgs` (`:4184-4258`). `callScan` (`:4171-4178`) records paths, whether an
egress target was seen, parsed egress hosts, sensitive matches, protected
matches, and ambiguity.

Argument key sets are hard-coded at `:3867-3934`:

- `contentKeys` (`:3867-3874`) are never treated as paths or network targets.
- `urlKeys` (`:3905-3907`) always imply egress.
- `destinationKeys` (`:3912-3928`) imply egress even for a bare hostname.
- `pathKeys` (`:3889-3903`) are the only values treated as paths for grants and
  scratch rules. Policy `path_keys` can add per-tool keys (`:4203-4204`).
- `egressSchemes` (`:3930-3934`) covers `http`, `https`, `ftp`, `ftps`, `sftp`,
  `ssh`, `smb`, `nfs`, `ws`, `wss`, `mailto`, and `file`.

For a string value, `scanArgs` checks in order: content key, URL/destination
key or URL/URI/IP shape, path key, host:port shape, protected target, sensitive
path, then path-like or path-syntax ambiguity (`:4193-4243`). An ambiguous
non-content value disqualifies grants and scratch rules, but does not itself
produce an error.

Sensitive matching:

- `defaultSensitivePaths` (`:3939-3952`) contains `.git`, `.env*`, `id_rsa*`,
  `id_ed25519*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, and a list of config files
  such as `go.mod`, `package.json`, `Makefile`, `Dockerfile`, `pyproject.toml`.
- Policy `sensitive_paths` are merged with the defaults; defaults cannot be
  removed (`:3962-3976`).
- `isSensitivePathParts` (`:4504-4537`) checks every path component and the
  basename, normalizes both slash directions, and strips invisible characters
  before matching.
- Protected agent-instruction and persistence targets are a separate table
  (`:4018-4068`): `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Cursor/Windsurf rules,
  MCP/editor config, CI workflows, `.git/hooks`, shell startup, cron, launchd,
  systemd user units, and Windows Startup.
- `protectedTargetPath` / `protectedCall` (`:4110-4164`) also check relative
  names against scratch roots and grant directories, so a symlink inside an
  approved root cannot hide a protected target.

Path comparison uses `canonicalPath` (`:4689-4695`), which makes the path
absolute without cleaning `..` before symlink resolution (`:4576-4618`), then
resolves the longest existing prefix (`:4639-4685`). `inside` (`:4779-4803`)
re-resolves the approved root, compares filesystem case sensitivity, rejects
environment/drive-relative/control-character forms, and checks the resolved
target is inside the root. This is a check, not a sandbox; a race between check
and write remains possible.

`scan.egress` hosts are matched textually against policy allow/deny patterns
(`:4353-4392`, `:4397-4444`). DNS is not resolved, redirects are not followed,
and the actual connection is not inspected.

Policy classes are `read`, `write`, `exec`, and `egress`. `write` and `exec` are
both sinks after taint; `egress` gets the additional allowlisted-host shortcut.
Unknown tools default to `exec` (`classFor`, `:4343-4351`). Built-in profiles
(`:2239-2530`) pre-classify common servers and are selected by command/package
token or `--name` (`:2612-2635`); policy entries then override individual tools
(`:1637-1670`).

## 9. CLI flags and the code they reach

### 9.1 Common proxy flags

The stdio path defines these in `main` (`:236-247`); the HTTP path defines the
same names through `registerGuardFlags` (`:536-554`) and `runProxyCommand`
(`:591-719`).

| Flag | Parsed at | What it reaches |
|---|---|---|
| `proxy --listen` | `:594` | `normalizeListenAddr` (`:721-741`); default `127.0.0.1:8080`; empty/`localhost` host becomes `127.0.0.1`; `net.Listen` in `runProxyCommand` (`:658-663`). |
| `proxy --upstream` | `:595` | URL validation (`:610-637`), `resolveUpstream` (`:1012-1030`), `http.Client` request (`doUpstream`, `:972-1011`), redacted audit field (`:671-682`). Auth headers from the client are copied by `copyRequestHeaders` (`:1031-1041`). |
| `--name` | `:236` | `nameExplicit` (`:466`), default from command basename for stdio or upstream host for `proxy` (`:467-478`, `defaultProxyName` `:743-760`), audit filename (`:489`), policy server lookup (`:506`, `:1266-1269`), pin filename (`:3815`), clear-taint control hash (`:5468`), `start` audit event (`:307`). |
| `--state-dir` | `:237` | Default `~/.sylenix-poc` (`:479-486`), `MkdirAll` (`:486`), audit file (`:489`), policy autoload (`:506`, `:1252`), pin file (`:3815`), control/request/result files (`:5468-5478`). |
| `--policy` | `:238` | `loadPolicyForRun` (`:506`, definition `:1238-1272`), strict parse (`:1329-1355`), validation (`:1389-1503`), `applyPolicy` (`:1573-1671`), deprecation notes (`:1827-1844`). Explicit path wins over `<state-dir>/policy.yaml`. |
| `--readonly` | `:239` | `applyPolicy` (`:1608-1612`) sets `readonly` and `readonlyOverride`; `classFor` returns `read` (`:4343-4351`); `fromHost` forwards read-class calls before hard blocks (`:3498-3502`). Replaces policy/profile read entries when explicitly set. |
| `--trust` | `:240` | `applyPolicy` (`:1613-1617`); `fromServer` skips taint and datamarking for trusted `tools/call` results (`:3676-3678`). Replaces policy trust entries when explicitly set. |
| `--approve` | `:241` | Validated when explicitly set (`:422-425`); `applyPolicy` (`:1590-1601`); protected-target handling (`:3531`); dialog branch (`:3566-3579`); `askHuman` (`:4914-4965`); default deny (`:3580-3582`). |
| `--no-spotlight` | `:242` | `applyPolicy` (`:1594-1604`) sets `spotlight`; `fromServer` skips `datamark` for tool results (`:3680-3682`); `datamark` (`:3718-3764`). Note this also skips invisible-character stripping, not only the wrapper. |
| `--reset-pins` | `:243` | `loadPins` (`:286`, `:3819-3823`): removes the pin file, logs `pins_reset`, then repins on the next `tools/list`. |
| `--allow-write-under` | `:245` | Repeatable `stringList`; parsed into `scratchRule` (`:427-441`), canonicalized at startup; `applyPolicy` (`:1619-1623`); scratch branch (`:3561-3565`); `scratchAllows` (`:4895-4907`); `protectedCall` checks relative names (`:4144-4150`); `start` event logs the raw specs (`:307-310`). |
| `--grant` | `:247` | Repeatable `stringList`; parsed into seeded grants (`:442-465`); stored in `Guard.grants` (`:497`); `grantAllows` (`:3556-3560`, `:4866-4890`); protected calls require a human grant (`:4877`); dialog grant recording (`:3570-3573`). |

### 9.2 Subcommand flags

| Command | Flag | Parsed at | What it reaches |
|---|---|---|---|
| `install` | `--yes` | `:7553` | Skips confirmation before config/policy writes (`:7641-7682`). |
| `install` | `--dry-run` | `:7554` | Shows config diff without writing; skips policy/allowlist update (`:7606-7637`, `:7641-7682`). |
| `install` | `--policy` | `:7558` | `policyWritePath` / `writePolicyFile` (`:7606-7636`, `:7662-7682`, `:2772-2784`, `:2868-2880`), and pinned into the wrapper (`:7583-7601`). |
| `install` | `--state-dir` | `:7559` | Default policy location and pinned into the wrapper (`:7583-7601`, `:7606-7611`). |
| `uninstall` | `--yes`, `--dry-run` | `:7553-7554` | Same `runConfigCommand` path, `action == "uninstall"` (`:7641-7661`). |
| `allow` | `--policy` | `:2086` | `policyWritePath` (`:2135`), `loadPolicyForUpdate` (`:2153`), `writePolicyFile` (`:2166`). |
| `allow` | `--state-dir` | `:2087` | Default policy location (`:2135`). |
| `allow` | `--yes` | `:2088` | Skips the confirmation prompt (`:2144-2152`). |
| `policy` | none | `:1846-1885` | Positional `validate <file>` or `print-default`. |
| `doctor` | `--json` | `:6276` | JSON report instead of human text (`:6311-6317`). |
| `doctor` | `--policy` | `:6277` | Explicit policy for the audit (`:6303-6305`, `:6334-6337`). |
| `doctor` | `--state-dir` | `:6278` | Default state dir when a wrapper does not pin one (`:6305`). |
| `doctor` | `--require-signatures` | `:6279` | Reports unsigned policy/pins as findings (`:6306`, `:6754-6814`). |
| `clear-taint` | `--name` | `:5772` | Session name; required (`:5784-5787`); control lookup (`:5802`). |
| `clear-taint` | `--state-dir` | `:5773` | State dir, default `~/.sylenix-poc` (`:5792-5801`). |
| `stats` | `--name` | `:5939` | Reads `<state-dir>/audit-<name>.jsonl` (`:5966-5978`). |
| `stats` | `--file` | `:5940` | Reads the named audit log directly (`:5966`). |
| `stats` | `--state-dir` | `:5941` | Only valid with `--name` (`:5958-5961`). |

Flag/policy precedence in `applyPolicy` (`:1573-1671`): `--approve` overrides
`approval`, `--no-spotlight` overrides `spotlight`, `--readonly` replaces policy
and profile read classes, `--trust` replaces policy trust, and
`--allow-write-under` replaces policy `allow_paths`. `--grant` is flag-only.

## 10. State on disk

Default state directory: `~/.sylenix-poc` (`:479-486`). It is created with
`0700`, but an existing directory is not chmod-ed.

| File | Format | Mode | Lifecycle / code |
|---|---|---|---|
| `audit-<name>.jsonl` | One JSON object per line. Base fields: `ts` (RFC3339Nano UTC), `server`, `event`; event-specific fields include `tool`, `rule`, `arg_keys`, `origin`, `class`, `granted`, `scope`, `source`, `version`, `profile`, `command`. Never argument values. | `0600` on create | Opened append-only at startup (`:489`); written by `event` (`:5358-5367`); no rotation or fsync. |
| `pins-<name>.json` | Indented JSON object: tool name -> 64-character hex SHA-256 of the JSON-marshaled tool definition. | `0600` | `pinsPath` (`:3815`); `loadPins` (`:3819-3849`); `savePins` (`:3851-3859`); atomic temp+rename. |
| `policy.yaml` | Version-1 YAML (strict subset) or JSON. Schema: version, profile, approval, spotlight, sensitive_paths, egress allow/deny hosts, allowlist, servers/tools. | `0600` when written by Guard | Auto-loaded from state dir or `--policy` (`:1238-1272`); strict parse/validation (`:1329-1503`); canonical write drops comments (`:2691-2770`, `:2868-2880`). |
| `control-<hash>.json` | JSON `{version,name,pid,nonce,started_at,heartbeat}`. `<hash>` is the first 16 bytes of SHA-256(name), hex. | `0600` | Created by `startGuardControl` (`:5530-5551`); heartbeat every 2 s (`:5558-5569`); stale after 15 s (`:5857-5888`); removed on exit (`:5737-5755`). |
| `clear-taint-request-<hash>.json` | JSON `{version,nonce,guard_started,request_id,requested_at}`. | `0600` | Written by CLI (`:5812-5823`); polled and removed by guard (`:5603-5643`); TTL 2 min. |
| `clear-taint-result-<hash>-<request_id>.json` | JSON `{version,request_id,status,who,at,note}`. | `0600` | Written by guard (`:5716-5724`); read and removed by CLI (`:5890-5920`); stale results removed at next guard start (`:5726-5735`). |
| `<config>.sylenix-backup-<UTC timestamp>` | Byte-for-byte copy of an MCP client config before `install`/`uninstall`. | Original file mode | `writeConfigBackup` (`:8234-8252`). |
| `policy.yaml` written by `install`/`allow` | Canonical YAML; comments/formatting not preserved. | `0600` | `writePolicyFile` (`:2868-2873`). |

No tokens or auth headers are stored. The HTTP proxy keeps only the configured
upstream URL and an in-memory HTTP client; `Mcp-Session-Id` is passed through and
never written to disk. The audit log records tool names, argument key names,
paths/scope values, and command paths, but not argument values or header values
(`event`, `:5358-5367`; also `POC_SPIKE.md:90`).

## 11. What `make check` runs

`make check` is the aggregate target at `Makefile:47`:

```text
check: fmt vet selftest probe-test proxy-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test
```

It runs, in order:

1. **`fmt`** (`Makefile:9-10`): fails if `gofmt -l cmd` reports any file.
2. **`vet`** (`Makefile:12-13`): `CGO_ENABLED=0 go vet ./...`.
3. **`selftest`** (`Makefile:15-17`): builds the binary, then runs
   `python3 demo/selftest.py` and `python3 demo/selftest.py --policy`.
4. **`probe-test`** (`Makefile:19-24`): builds and runs the regression probes:
   `test_scratch_grant_bypass.py`, `test_protected_targets.py`,
   `test_policy.py`, `test_allowlist.py`, `test_install.py`.
5. **`proxy-test`** (`Makefile:26-27`): `tests/probes/test_http_proxy.py`, the
   stdio/HTTP parity, SSE, session, auth-header and pin-quarantine probes.
6. **`profile-test`** (`Makefile:29-30`): `test_profiles.py` for the built-in
   filesystem, git, GitHub, fetch, shell, Slack, Postgres, browser, Notion, and
   Jira profiles.
7. **`replay-test`** (`Makefile:32-33`): `scripts/replay_profile_session.py`,
   which reports approval prompts per active hour for the recorded filesystem
   session.
8. **`summary-test`** (`Makefile:35-36`): runs `scripts/summarize_audit.py` on
   `demo/fixtures/audit_sample.jsonl`, strips CRs with `tr`, and diffs against
   `demo/fixtures/audit_sample.expected.txt`.
9. **`doctor-test`** (`Makefile:38-39`): `tests/probes/test_doctor.py`.
10. **`clear-taint-test`** (`Makefile:41-42`):
    `tests/probes/test_clear_taint.py`.
11. **`stats-test`** (`Makefile:44-45`): `tests/probes/test_stats.py`.

`make check` does **not** run `go test ./...` (there are no Go tests), and does
not run the agent harness or sweep. The harness is a separate target:
`make harness-scripted` (`Makefile:49-50`) uses
`.venv/bin/python demo/harness.py --agent scripted --runs 3`; that path is
Unix-style and does not work as written on Windows.

On Windows, `make check` needs a POSIX shell because `fmt` uses `test`, and
`summary-test` uses `tr` and `diff` (`README.md:119-120`).

## 12. What `demo/selftest.py` checks

`demo/selftest.py` is a dependency-free protocol test. It starts a fresh guard
per case in front of `demo/fake_server.py` (`demo/selftest.py:50-65`), so each
case begins with a clean taint state. It runs twice under `make check`: flags
mode and `--policy` mode. The policy mode writes an equivalent state-dir policy
with `read_ticket: class: read` instead of passing `--readonly read_ticket`
(`demo/selftest.py:25-35`, `:55-59`). It uses `bin/sylenix-guard` or
`bin/sylenix-guard.exe` (`:18-23`) and its test handshake uses protocol version
`2025-06-18` (`:95`).

The cases, in execution order (`demo/selftest.py:516-520`):

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
   `main.go:1031-1041`) and never logged or persisted.
2. **Taint is per guard process and per wrapped server.** It does not cover
   host built-in tools, attachments, or pasted text, and restarting the guard
   starts a clean session (`POC_SPIKE.md:217-224`; `main.go:494-497`). This is
   fundamental to the current design.
3. **No confidentiality latch.** Reading a secret and then calling a read-only
   tool is not tracked (`POC_SPIKE.md:226`).
4. **The HTTP proxy does not enforce the server-command allowlist.** The
   allowlist is a launch control for a child process (`checkServerAllowed`,
   `main.go:1775-1825`); `proxy` has no child command and skips it. A policy with
   `allowlist_enforced: true` therefore does not restrict `--upstream`.
5. **SSE resumability is left to the client and upstream.** The proxy forwards
   `Last-Event-ID` and SSE event IDs, but keeps no replay buffer and does not
   persist streams (`copyRequestHeaders`, `main.go:1031-1041`; `streamSSE`,
   `:1101-1184`). A broken connection loses in-flight events unless the upstream
   can replay them. This matches the 2026-07-28 direction, which removes
   resumability, but is a real gap for 2025-11-25 servers that expect the client
   to resume.
6. **Auth-header pass-through is broad by design.** Every end-to-end request
   header except the explicit hop-by-hop/Host/Content-Length/Origin set is
   copied upstream (`copyRequestHeaders`, `main.go:1031-1041`). That includes
   `Authorization`, `Cookie`, `X-Api-Key` and any custom auth header the client
   sends. The guard does not validate the credential, scope it to a host, or
   replace it. Only the configured `--upstream` sees it.
7. **The HTTP listener is loopback-only by default, but `--listen` can expose
   it.** `normalizeListenAddr` maps an empty host or `localhost` to
   `127.0.0.1` (`main.go:721-735`), but an explicit `0.0.0.0` or LAN address is
   accepted. The listener itself is plain HTTP; use a loopback address or a
   trusted tunnel/reverse proxy for anything else. Origin checking is not a
   substitute for authentication (`originAllowed`, `:811-832`).
8. **Session IDs are passed through, not mapped per client.** A client that
   presents another client's `Mcp-Session-Id` is forwarded with that ID; the
   proxy adds no session isolation of its own (`copyRequestHeaders`,
   `main.go:1031-1041`). The upstream is responsible for authenticating the
   session, as it would be without the proxy.

### Enforcement gaps that are easy to trip over

9. **`--readonly` / `class: read` bypasses every sink check, including
   `EGRESS_TARGET` and `SENSITIVE_TARGET`.** The read check is before the hard
   blocks (`main.go:3497-3502`), and `classFor` returns `read` for anything on
   the list (`:4343-4351`). `POC_SPIKE.md:221` calls this a trust decision. A
   mis-listed tool defeats the latch.
10. **`--trust` suppresses taint and datamarking for that tool's results.**
   `fromServer` returns early for trusted `tools/call` results (`main.go:3676-3678`).
   Trust only applies to `tools/call`, not `resources/read` or `prompts/get`.
11. **`--no-spotlight` disables more than the wrapper.** It skips the entire
   `datamark` call (`main.go:3680-3682`), so invisible-character stripping and
   `structuredContent` cleanup are skipped too. The flag help says only "do not
   datamark" (`:242`), and `POC_SPIKE.md:179` says "Skip datamarking".
12. **Argument classification is a heuristic.** Only known path keys are treated
   as paths; a path under a content-named key is ignored (`main.go:4195-4196`),
   and an unknown-shaped value can be classified as ambiguous or not path-like
   at all (`:4240-4243`, `looksLikePath` `:4446-4458`). A tool-wide `--grant`
   can therefore cover calls whose path the guard did not recognize. This is
   acknowledged in `POC_SPIKE.md:231`.
13. **Pinning is trust on first use and does not sanitize the first
   definition.** A first `tools/list` can contain prompt-injected tool
   descriptions; the guard pins them rather than rejecting them
   (`main.go:3768-3808`, `POC_SPIKE.md:227`). Pin files are unsigned and
   same-user writable.
14. **A later identical `tools/list` un-quarantines a tool.** `inspectToolsList`
   deletes the quarantine entry when the definition matches the old pin
   (`main.go:3802`). That is probably intended recovery, but it means a server
   that alternates between two definitions moves the tool in and out of
   quarantine; calls are blocked only during the quarantined period.
15. **`tools/list` pinning is skipped silently if the result shape is not the
    expected `{tools: [...]}`.** `inspectToolsList` returns without error on
    unmarshal failure (`main.go:3772-3774`), so no pins and no quarantine are
    recorded for that response.
16. **The guard does not reject duplicate keys in server frames.** Host frames
    get the `hasDuplicateKeys` check (`main.go:3454-3457`), but `fromServer`
    decodes with plain `json.Unmarshal` (`:3642`) and never checks duplicates.
    A malicious server can present one value to the guard and another to a
    host whose JSON parser resolves duplicates differently. The same issue
    exists inside tool definitions and policy JSON only insofar as the guard
    decodes them.
17. **Datamarking is structural, not a real content boundary.** It only wraps
    `content[].text` and only neutralizes the exact lower-case
    `</untrusted_tool_result` string (`main.go:3735`). Case variants, unusual
    result shapes, resource/prompt results, and non-text content are not
    wrapped (`:3671-3682`, `:3719-3726`). `POC_SPIKE.md:228` acknowledges that
    spotlighting is friction, not protection.

### Path, egress, and approval risks

18. **Sensitive/egress checks are textual and path-based, not a sandbox.**
    Egress matching compares host strings and does not resolve DNS, follow
    redirects, or pin IPs (`main.go:4353-4444`, `POC_SPIKE.md:238`). Scratch
    path checks resolve symlinks but leave a check-to-write race
    (`main.go:4779-4803`, `POC_SPIKE.md:232`).
19. **A directory-scoped grant is broader than one call.** `addGrant` records
    tool plus directory; `grantAllows` allows any call to that tool whose paths
    stay inside the directory for 15 minutes (`main.go:4856-4890`). A human
    approval for one protected file can therefore cover other protected files
    in the same directory while the grant is live (`:4877`). `POC_SPIKE.md:230`
    documents the broader grant scope.
20. **Dialog mode blocks the calling transport while a dialog is open.**
    `askHuman` runs synchronously in the stdio host-to-server goroutine
    (`main.go:3566-3569`, `:4914-4965`; `POC_SPIKE.md:229`). In stdio mode that
    stalls the whole session; in HTTP mode only that request's handler waits,
    but concurrent requests can each open a dialog. A slow or stuck dialog
    stalls the call for up to 60 seconds.
21. **Dialog text is truncated and sanitized, not a trustworthy rendering of
    the call.** Arguments are cut at 300 characters and control/invisible
    characters are removed (`cleanForDialog`, `:5105-5122`; `askHuman`,
    `:4914-4917`). Confusable or long arguments can still mislead a human.

### State, audit, and local-process risks

22. **`--name` is validated at startup, but `stats --name` still concatenates
    an unvalidated name.** `prepareGuard` now uses `validDoctorName`
    (`main.go:474`, `:7172-7183`), so the proxy and stdio paths reject path
    separators. `stats --name` still builds `audit-<name>.jsonl` directly
    (`:5978`), so a caller can read another `.jsonl` path relative to the state
    directory. Use a simple name and a unique state directory.
23. **Audit and pin write errors are ignored.** `event` discards the
    `log.Write` result (`main.go:5364-5366`), and `savePins` discards both the
    temp-file and rename errors (`:3851-3859`). A full or read-only state
    directory can silently lose audit records or pins while the proxy keeps
    running. There is no fsync or rotation.
24. **Existing state-dir and audit-file permissions are not tightened.**
    `MkdirAll(..., 0700)` and `OpenFile(..., 0600)` only set modes on creation
    (`main.go:486-491`); an existing `0755` directory or `0644` audit file stays
    that way.
25. **Clear-taint control files are same-user state, not authentication.**
    A same-user process, including the wrapped server, can request a dialog
    (`main.go:5530-5755`; `POC_SPIKE.md:223`). Only a human click clears the
    latch, but the dialog is local and not biometric. A successful clear does
    not revoke grants or quarantines (`:3711-3716`).
26. **Two guards using the same `--name` and state dir share pins, audit, and
    control paths.** The control path is keyed by a hash of the name
    (`main.go:5463-5478`), and `cleanupStaleFiles` removes request/result files
    for that name at startup (`:5726-5735`). Use a unique name per guard;
    `POC_SPIKE.md:223` makes the same point for clear-taint.
27. **`install` and `allow` persist and print server arguments.** The allowlist
    is an exact command/args record (`main.go:88-94`, `:1785-1793`), and
    `allow`/`install` print the arguments to the terminal
    (`:2140-2143`, `:7665-7669`) before writing them to `policy.yaml`. If a
    server passes a token in an argument, it can end up in the policy file and
    terminal scrollback. The audit log itself does not record argument values.
28. **The server's stderr is inherited, not mediated.** `cmd.Stderr = os.Stderr`
    (`main.go:302`) means a server can write directly to the operator's terminal,
    including escape sequences or secrets, without the guard inspecting it.
29. **The pending-request map never expires.** `track` adds ids and only
    `take`/`failPending` remove them (`main.go:5290-5343`); a server that never
    answers an id leaves an entry for the life of the process
    (`POC_SPIKE.md:241`).
30. **Signal cleanup is minimal.** The signal goroutine stops control, kills the
    child, and exits (`main.go:317-324`); descendants of a wrapper such as
    `npx` are not killed (`POC_SPIKE.md:240`).

### Build, test, and configuration clarity

31. **`make check` is POSIX-shell dependent on Windows.** `fmt` uses `test`
    (`Makefile:9-10`), and `summary-test` uses `tr` and `diff`
    (`Makefile:35-36`); `README.md:119-120` says Git Bash or WSL is required.
    `make harness-scripted` also hard-codes `.venv/bin/python`
    (`Makefile:49-50`), which is not a Windows path.
32. **There are no Go unit tests.** `make check` runs `go vet` and Python
    integration probes, but not `go test ./...` (`Makefile:47`). A regression
    in an unexercised helper can pass the suite.
33. **Policy loading is one-shot and unsigned.** The file is read at startup
    and not watched (`main.go:506-523`; `POC_SPIKE.md:235`). A policy file that
    exists but cannot be parsed stops the guard; a policy file with several
    `servers` entries must contain the active `--name` (`:1266-1269`).
34. **`--policy` / policy precedence can surprise.** `--readonly` replaces both
    policy and profile read classes, `--trust` replaces policy trust, and
    `--allow-write-under` replaces all policy `allow_paths` (`main.go:1608-1623`).
    This is documented but easy to miss; a flag intended as an addition can
    silently remove profile defaults.
35. **Allowlist enforcement can be explicitly disabled with
    `allowlist_enforced: false` even when entries exist.** `applyPolicy` honors
    an explicit false (`main.go:1582-1588`). `docs/POLICY.md:148-150` only
    describes the omitted-field behavior; the explicit-false-with-entries case
    is easy to misread.
