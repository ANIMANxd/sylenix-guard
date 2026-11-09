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
before parsing proxy flags (`:225-244`).

### 1.1 Streamable HTTP proxy mode

`proxy` is a separate transport front end over the same `Guard` decision core:

- `--listen` defaults to `127.0.0.1:8633`; an empty host or `localhost` is
  normalized to `127.0.0.1` (`normalizeListenAddr`, `:753-773`).
- `--upstream` is required and must be an absolute `http` or `https` URL
  (`:651-667`). Its query string is forwarded to the upstream but redacted from
  logs and audit events (`redactURL`, `:795-804`).
- `POST` carries one JSON-RPC message. `GET` opens the optional server-to-client
  SSE stream. `DELETE` terminates the upstream session. `OPTIONS` answers
  locally (`ServeHTTP`, `:822-841`).
- `Origin` is checked before any request is forwarded. Missing Origin is
  allowed; loopback origins and the request host are allowed; anything else
  gets HTTP 403 (`originAllowed`, `:843-864`).
- Request headers are copied end to end except hop-by-hop headers, `Host`,
  `Content-Length`, `Accept-Encoding`, and `Origin` (`copyRequestHeaders`,
  `:1063-1073`). `Authorization`, `Cookie`, `Mcp-Session-Id`,
  `MCP-Protocol-Version`, and `Last-Event-ID` therefore reach the upstream.
  Header values are never logged.
- `Mcp-Session-Id` is passed through in both directions. The proxy does not
  mint, store, or persist session IDs. This is valid for the session-bearing
  MCP 2025-11-25 revision; it also works with the stateless 2026-07-28 shape
  because the header is simply absent.
- Upstream `content-type: application/json` bodies are inspected by
  `fromServer` and returned as JSON. `text/event-stream` bodies are parsed event
  by event, inspected by `fromServer`, and re-emitted as SSE (`streamSSE`,
  `:1133-1216`). SSE comments, `event:`, `id:`, `retry:` and multi-line `data:`
  fields are preserved.
- A blocked host message returns a JSON-RPC error immediately without contacting
  the upstream (`handlePost`, `:866-947`). A notification that the guard drops
  gets HTTP 202.
- Upstream failures and oversized frames fail the pending request with
  `UPSTREAM_ERROR`, `SERVER_FRAME_TOO_LARGE`, or `SERVER_STREAM_CLOSED` rather
  than leaving the client waiting (`failOne`, `:5845-5851`; `finishPending`,
  `:1254-1262`).

The legacy HTTP+SSE transport from 2024-11-05 (separate SSE and POST endpoints)
is not implemented. `install` still skips remote config entries
(`:2376-2417`, `:8573-8590`), and `doctor` reports them as
`REMOTE_NOT_COVERED` (`:7070-7072`) because installing a remote transport is a
client-configuration decision, not a wrapper decision; the finding now points at
manual `proxy` configuration.

### 1.2 Signing policy and pin stores

Signing is an Ed25519 detached-signature layer over the exact bytes of
`policy.yaml` and `pins-<name>.json`:

- `keys init` generates a PKCS#8 private key and PKIX public key
  (`runKeysCommand`, `:1395-1494`). The default path is outside the state
  directory, `~/.sylenix-keys/policy-signing.key`; a key inside the configured
  state directory is refused. The private key is written `0600` and the command
  prints a warning that anyone who can read it can loosen Guard.
- `policy sign --policy PATH --key PATH` validates the policy and writes
  `policy.yaml.sig`, a raw 64-byte signature (`runPolicySignCommand`,
  `:2198-2247`; `signFileDetached`, `:1386-1393`). `policy verify` and
  `pins sign` / `pins verify` cover diagnostics and pre-signing
  (`runPolicyVerifyCommand`, `:2249-2290`; `runPinsCommand`, `:1496-1580`).
- `--policy-pubkey` loads the verification key; `--policy-key` loads the private
  key, derives its public key and enables signing of new pin stores. If both are
  set, the public keys must match (`loadGuardSigningKeys`, `:1275-1297`).
- Policy verification happens in `loadPolicyForRun` before parsing
  (`:1582-1624`). Pin verification happens in `loadPins` before JSON parsing and
  hash validation (`:4295-4337`). A missing, truncated, wrong-key or changed
  signature returns an error and the process exits 2.
- `savePins` signs the exact JSON bytes before writing the store
  (`:4340-4394`). Without a private key but with verification enabled it keeps
  pins in memory and does not write an unsigned store. `--reset-pins` removes
  both the pins and the `.sig`.
- `writePolicyFile` and `writeDefaultPolicyFile` remove a stale policy
  signature after any canonical rewrite (`:3332-3354`), so `install` and `allow`
  leave a fail-closed missing signature rather than a valid-looking stale one.

This detects modification, not rollback: an older signed policy/pin pair can be
restored. The private key is only as safe as its file permissions and the
machine account; there is no HSM or remote signer.

## 2. Entry point and startup sequence

`main()` is at `cmd/sylenix-guard/main.go:225`.

1. Subcommand dispatch (`:226-242`). If `os.Args[1]` is a known subcommand, run
   it and exit. Otherwise fall through to proxy mode.
2. Proxy flag parsing (`:250-264`). `flag.Visit` records which flags were
   explicitly supplied (`:266-267`), so flags can override policy only when the
   operator actually set them.
3. Input validation and flag expansion:
   - `--approve` must be `deny` or `dialog` when explicitly set (`:440-443`).
   - `--allow-write-under` becomes `[]scratchRule`, with `TOOL=DIR` support
     (`:445-459`).
   - `--grant` becomes seeded in-memory grants, with `TOOL[:DIR]=DURATION`
     parsing (`:460-483`).
4. Name and state-directory defaults (`:484-504`). The default name is the
   server command's basename; the default state directory is `~/.sylenix-poc`.
5. State directory creation with mode `0700` and audit-log open with mode
   `0600` (`:504-509`).
6. Signing-key load (`:512-516`) and `Guard` construction (`:518-531`).
7. Policy resolution and application (`:532-549`): explicit `--policy`, else
   `<state-dir>/policy.yaml`, else built-in defaults; signature verification when
   a key is configured; profile selection; flag overrides.
8. Server allowlist check before the child is launched (`:294-303`). A refusal
   exits `2` and writes `SERVER_NOT_ALLOWED` to the audit log.
9. Pin-file load; an untrusted pin file exits `2` unless `--reset-pins`
   (`:304-307`).
10. Child process start with stdin/stdout pipes; stderr is inherited
    (`:309-324`).
11. Start event and clear-taint control loop (`:325-333`).
12. Signal handler (`:336-343`), then two long-lived goroutines: host-to-server
    (`:353-385`) and server-to-host (`:387-418`).
13. Wait for the server-to-host loop and the child, stop the control loop, log
    the exit, and exit with the child's code (`:419-429`).

The child is killed five seconds after either side closes its input, on a
signal, or when the guard shuts down (`:336-343`, `:327-334`, `:404-416`).

Proxy mode shares steps 3 through 9 through `prepareGuard` (`:435-553`). It then
binds the listener (`runProxyCommand`, `:621-751`), starts the same clear-taint
control loop, emits a `start` event with `transport: streamable-http`, and serves
HTTP until a signal or listener error. It does not check the server-command
allowlist because there is no child command to launch; the stdio allowlist
remains a launch-only control.

## 3. Main data structures

All in `cmd/sylenix-guard/main.go`:

| Type | Purpose | Location |
|---|---|---|
| `Guard` | Entire per-process state: policy, taint, pending requests, pins, quarantines, grants, output writer, audit writer | `:164-204` |
| `guardOptions` | Shared startup configuration for stdio and HTTP | `:208-223` |
| `frame` | `map[string]json.RawMessage` for one JSON-RPC object | `:126` |
| `pendingReq` | Tracks the method and tool name for an outstanding request id | `:128-131` |
| `scratchRule` | One `--allow-write-under` entry: optional tool plus directory | `:135-138` |
| `grant` | One time-bounded approval: tool, optional directory, expiry, human/protected flags | `:142-148` |
| `policyFile` | Strict on-disk policy schema | `:79-89` |
| `policyTool` | Per-tool class, extra path keys, allow paths, trust | `:110-115` |
| `policyProfile` | Built-in classification table for a known server family | `:119-124` |
| `guardFlagValues` | Common proxy flags registered by both dispatch paths | `:557-584` |
| `sseEvent` | One parsed server-sent event | `:587-597` |
| `proxyHandler` | HTTP transport state: Guard, upstream URL, HTTP client | `:599-603` |
| `guardControl` | Clear-taint control-file implementation | `:5966-5978` |
| `controlFile`, `clearRequest`, `clearResult` | On-disk control/request/result JSON shapes | `:5940-5964` |

Concurrency boundaries:

- `Guard.mu` protects taint state, `pending`, `pins`, `quarantined`, and
  `grants` (`:186-192`). Policy maps are built before the goroutines start and
  are read-only afterwards.
- `Guard.outMu` serializes every write to the host's stdout (`:196`, `:5862-5871`).
  Proxy mode points `out` at `io.Discard`; responses go through the HTTP handler.
- `Guard.logMu` serializes audit-log writes (`:199`, `:5875-5884`).
- `serverGone` is an `atomic.Bool` set when the server's stdout closes (`:194`,
  `:405`).

## 4. Request path: host -> Guard -> server

In stdio mode the host reader is `readFrame` (`:5772-5796`), called in the host goroutine
(`:345-377`). It enforces the 10 MiB frame limit (`:49`) and a 64 MiB discard
budget (`:50`, `:5788-5790`). Oversize host frames are answered with `-32600
FRAME_TOO_LARGE` and id `null`; the connection survives unless the line cannot
be framed (`:356-363`).

In HTTP mode the POST body is bounded by the same `maxFrame` and passed to the
same `fromHost` (`handlePost`, `:866-947`). The explicit-allow branch then sends
the original body to the upstream. Blocked requests get a JSON-RPC error body
with HTTP 200; notifications get HTTP 202. The HTTP transport never calls
`Guard.write`, so the stdio writer is not involved.

`Guard.fromHost` (`:3918-4058`) decides every host frame:

1. **Batch frames** (`:3920-3923`): top-level `[` is refused with `-32600
   BATCH_UNSUPPORTED`; not forwarded.
2. **Malformed JSON** (`:3924-3928`): `-32700 UNPARSEABLE`, id `null`; not
   forwarded.
3. **Duplicate keys anywhere in the JSON object** (`:3929-3932`): `-32600
   DUPLICATE_KEYS`, id `null`; not forwarded. This is a deliberate parser
   differential defense.
4. **Host responses to server requests** (`:3933-3938`): a frame with no
   `method` is forwarded as a response without further inspection.
5. **Server already gone** (`:3939-3941`): requests get `-32000
   SERVER_STREAM_CLOSED`; notifications get no reply.
6. **Duplicate pending id** (`:3942-3947`): `-32600 DUPLICATE_ID`, id `null`;
   the first request keeps its identity.
7. **Non-`tools/call` methods** (`:3948-3951`): tracked by id, then forwarded.
8. **`tools/call` parsing** (`:3953-3960`): missing or non-object `params`, or
   an empty tool name, gets `-32000 UNPARSEABLE_CALL`.
9. **Quarantine** (`:3962-3971`): a quarantined tool is blocked with `-32001
   MANIFEST_QUARANTINE`, even in a clean session.
10. **Clean session or read-class tool** (`:3972-3977`): forwarded. The class is
    `read` if the tool is in `--readonly`, a profile read default, or policy
    `class: read` (`classFor`, `:4860-4868`). This check is before every hard
    block.
11. **Tainted non-read call** (`:3979-4057`) is decided in this order:
    1. **`EGRESS_TARGET`** (`:3983-3997`): any network-shaped argument, unless
       every parsed host is on the policy egress allowlist and none is on the
       denylist. The hard block is not dialog-approvable and is not covered by a
       grant or scratch rule.
    2. **`SENSITIVE_TARGET`** (`:3998-4002`): any sensitive path match. Also not
       dialog-approvable, grant-covered, or scratch-covered.
    3. **Protected persistence/agent-instruction target** (`:4003-4010`): if the
       target is protected and approval mode is not `dialog`, block with
       `SENSITIVE_TARGET`. With `--approve dialog`, it can reach a human.
    4. **Egress allowlist shortcut** (`:4011-4025`): an `egress`-class tool whose
       every destination is allowlisted can run without a prompt, unless the
       call is ambiguous or protected.
    5. **Live grant** (`:4026-4035`, `grantAllows` at `:5383-5407`): a
       time-bounded grant can allow the call only when there is no egress and no
       ambiguity, and every path stays inside the grant's directory (or the
       grant is tool-wide and paths resolve safely). Protected calls require a
       human-recorded protected grant.
    6. **Scratch write** (`:4036-4040`, `scratchAllows` at `:5412-5424`): no
       prompt while every path stays inside an `--allow-write-under` root. No
       recognizable path means no scratch shortcut.
    7. **Dialog** (`:4041-4054`, `askHuman` at `:5431-5482`): with
       `--approve dialog`, offer Deny / Allow Once / Allow Tool for 15m.
       A grant records a directory scope and is held in memory.
    8. **Default deny** (`:4055-4057`): `-32000 TAINT_SINK`.

A blocked request gets an error frame only when it has an id; notifications are
dropped silently (`replyIfRequest`, `:5902-5908`). Error data carries only a rule
name (`errorFrame`, `:5890-5900`).

## 5. Response path: server -> Guard -> host

In stdio mode the server reader is the same `readFrame` logic (`:379-418`).
Oversize server frames cannot be inspected or matched to a request, so the guard
latches taint, fails every pending request with `-32000 SERVER_FRAME_TOO_LARGE`,
and discards the frame (`:392-400`).

In HTTP mode JSON bodies are read with the same limit and passed to `fromServer`
(`handlePost`, `:866-947`). SSE responses are parsed by `streamSSE`
(`:1133-1216`): each `data:` payload is passed to `fromServer`, and the resulting
message is re-emitted with its `event:`/`id:`/`retry:` fields. A stream that ends
without the pending response gets a synthetic `SERVER_STREAM_CLOSED` error event
(`finishPending`, `:1254-1262`).

`Guard.fromServer` (`:4111-4160`) handles a server line:

1. **Unparseable server output** (`:4117-4122`): forwarded unchanged and taints
   with origin `unparseable_server_output`.
2. **Server request or notification** (`:4123-4134`): forwarded so the host can
   answer. If it carries text/resource content, the guard logs only the method
   and rule and latches with reason `TAINT_SERVER_REQUEST`.
   `serverMessageHasContent` is at `:4065-4109`; `sampling/createMessage` and
   `elicitation/create` always count, other methods are inspected against
   content-key names.
3. **Response matching** (`:4136-4141`): the id is removed from `pending`. An
   unmatched response is forwarded unchanged and taints with origin
   `unmatched_response`.
4. **`tools/list`** (`:4142-4145`): `inspectToolsList` pins or quarantines tool
   definitions before the line is forwarded.
5. **`tools/call`, `resources/read`, `prompts/get`** (`:4146-4158`): a
   `tools/call` result for a `--trust`ed tool is forwarded without taint or
   datamarking. Every other such result latches taint *before* the host can see
   it. `tools/call` text results are datamarked when spotlighting is enabled;
   resource and prompt results are not wrapped.
6. **Everything else** is forwarded unchanged.

`datamark` (`:4193-4239`) wraps each `text` content item in
`<untrusted_tool_result origin="..." integrity="untrusted">`, neutralizes the
literal lower-case closing tag, strips invisible characters, and strips
invisible characters from `structuredContent` strings without wrapping the
structured value. If the result shape is not the expected object/content array,
it returns the original line; taint has already been latched.

## 6. Taint lifecycle

Taint is in memory only. It begins clean in each new guard process.

**Set** by `latch` / `latchReason` (`:4162-4182`). The first latch records the
origin and emits `taint_latched`; later latches only set the boolean.

Triggers:

| Trigger | Code |
|---|---|
| Untrusted `tools/call` result | `:4146-4154`; `--trust` bypasses only this branch |
| `resources/read` or `prompts/get` result | `:4146-4154` |
| Unparseable server stdout line | `:4117-4122` |
| Server response whose id matches no pending request | `:4136-4141` |
| Server request/notification carrying content | `:4125-4132`, `:4065-4109` |
| Oversize server frame | `:392-396` (main server loop) |

**Cleared** only by `clearTaint` (`:4186-4191`), which is called only from the
human-approved clear-taint control path (`:6176-6231`). A successful clear emits
`CLEAR_TAINT` with `who`, `method: dialog`, and a request id. It does not revoke
grants, quarantines, or the server process. MCP tool calls, host methods, server
messages, and environment variables cannot clear the latch.

The `clear-taint` CLI (`:6286-6372`) writes a nonce- and guard-start-bound request
file into the state directory and waits for the running guard's result. The
guard polls every 200 ms (`:6088-6100`), validates version, nonce, start time,
request age, and request id (`:6120-6160`), then shows an OS dialog
(`askClearTaint`, `:5487-5528`). Denial, timeout, or an unavailable dialog keeps
the latch.

## 7. Tool pinning and quarantine

On a `tools/list` response, `inspectToolsList` (`:4243-4288`) does the following
for each tool with a non-empty name:

1. Marshal the decoded tool object to JSON. Go sorts map keys, so the encoding
   is stable for the same decoded value (`:4257`).
2. SHA-256 the encoding and hex-encode it.
3. Compare with the pin map (`old, seen := g.pins[name]`, `:4260`).
4. Quarantine if the tool contains invisible characters (`containsInvisible`,
   `:4264-4265`, `:5720-5738`) or if a previously seen definition now has a
   different hash (`:4266-4267`).
5. Otherwise remove any old quarantine for that name, and if this is first
   sight, store the hash and emit `tool_pinned` (`:4277-4282`).

Quarantine is a tool-name map to a reason string. A quarantined tool is blocked
before taint is even considered (`:3967-3971`). If a later `tools/list` returns
the original pinned definition again, the `delete(g.quarantined, name)` at
`:4277` removes the quarantine.

The pin file is `pins-<name>.json` (`:4290`). `loadPins` (`:4295-4338`) treats a
missing file as first use, but refuses to start if the file exists and is
unreadable, is not a JSON object, has an empty tool name, or has a value that is
not a 64-character hex SHA-256. `--reset-pins` deletes the file and logs
`pins_reset` (`:4295-4299`). `savePins` writes indented JSON and, when a private
key is configured, a detached signature (`:4340-4394`).

## 8. EGRESS and SENSITIVE classification

Classification happens only for a tainted, non-read `tools/call`, in
`scanArgs` (`:4701-4775`). `callScan` (`:4688-4695`) records paths, whether an
egress target was seen, parsed egress hosts, sensitive matches, protected
matches, and ambiguity.

Argument key sets are hard-coded at `:4384-4451`:

- `contentKeys` (`:4384-4391`) are never treated as paths or network targets.
- `urlKeys` (`:4422-4424`) always imply egress.
- `destinationKeys` (`:4429-4445`) imply egress even for a bare hostname.
- `pathKeys` (`:4406-4420`) are the only values treated as paths for grants and
  scratch rules. Policy `path_keys` can add per-tool keys (`:4720-4721`).
- `egressSchemes` (`:4447-4451`) covers `http`, `https`, `ftp`, `ftps`, `sftp`,
  `ssh`, `smb`, `nfs`, `ws`, `wss`, `mailto`, and `file`.

For a string value, `scanArgs` checks in order: content key, URL/destination
key or URL/URI/IP shape, path key, host:port shape, protected target, sensitive
path, then path-like or path-syntax ambiguity (`:4710-4760`). An ambiguous
non-content value disqualifies grants and scratch rules, but does not itself
produce an error.

Sensitive matching:

- `defaultSensitivePaths` (`:4456-4469`) contains `.git`, `.env*`, `id_rsa*`,
  `id_ed25519*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, and a list of config files
  such as `go.mod`, `package.json`, `Makefile`, `Dockerfile`, `pyproject.toml`.
- Policy `sensitive_paths` are merged with the defaults; defaults cannot be
  removed (`:4479-4493`).
- `isSensitivePathParts` (`:5021-5054`) checks every path component and the
  basename, normalizes both slash directions, and strips invisible characters
  before matching.
- Protected agent-instruction and persistence targets are a separate table
  (`:4535-4585`): `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Cursor/Windsurf rules,
  MCP/editor config, CI workflows, `.git/hooks`, shell startup, cron, launchd,
  systemd user units, and Windows Startup.
- `protectedTargetPath` / `protectedCall` (`:4627-4681`) also check relative
  names against scratch roots and grant directories, so a symlink inside an
  approved root cannot hide a protected target.

Path comparison uses `canonicalPath` (`:5206-5212`), which makes the path
absolute without cleaning `..` before symlink resolution (`:5093-5135`), then
resolves the longest existing prefix (`:5156-5202`). `inside` (`:5296-5320`)
re-resolves the approved root, compares filesystem case sensitivity, rejects
environment/drive-relative/control-character forms, and checks the resolved
target is inside the root. This is a check, not a sandbox; a race between check
and write remains possible.

`scan.egress` hosts are matched textually against policy allow/deny patterns
(`:4870-4909`, `:4914-4961`). DNS is not resolved, redirects are not followed,
and the actual connection is not inspected.

Policy classes are `read`, `write`, `exec`, and `egress`. `write` and `exec` are
both sinks after taint; `egress` gets the additional allowlisted-host shortcut.
Unknown tools default to `exec` (`classFor`, `:4860-4868`). Built-in profiles
(`:2703-2994`) pre-classify common servers and are selected by command/package
token or `--name` (`:3076-3099`); policy entries then override individual tools
(`:1989-2022`).

## 9. CLI flags and the code they reach

### 9.1 Common proxy flags

The stdio path defines these in `main` (`:246-257`); the HTTP path defines the
same names through `registerGuardFlags` (`:562-584`) and `runProxyCommand`
(`:621-751`).

| Flag | Parsed at | What it reaches |
|---|---|---|
| `proxy --listen` | `:624` | `normalizeListenAddr` (`:753-773`); default `127.0.0.1:8086`; empty/`localhost` host becomes `127.0.0.1`; `net.Listen` in `runProxyCommand` (`:690-695`). |
| `proxy --upstream` | `:625` | URL validation (`:640-667`), `resolveUpstream` (`:1044-1062`), `http.Client` request (`doUpstream`, `:1004-1043`), redacted audit field (`:701-712`). Auth headers from the client are copied by `copyRequestHeaders` (`:1063-1073`). |
| `--name` | `:250` | `nameExplicit` (`:484`), default from command basename for stdio or upstream host for `proxy` (`:485-496`, `defaultProxyName` `:775-792`), audit filename (`:507`), policy server lookup (`:532`, `:1618-1621`), pin filename (`:4290`), clear-taint control hash (`:5985`), `start` audit event (`:317`). |
| `--state-dir` | `:251` | Default `~/.sylenix-poc` (`:497-504`), `MkdirAll` (`:504`), audit file (`:507`), policy autoload (`:532`, `:1596`), pin file (`:4290`), control/request/result files (`:5985-5995`). |
| `--policy` | `:252` | `loadPolicyForRun` (`:532`, definition `:1582-1624`), strict parse (`:1681-1707`), validation (`:1741-1855`), `applyPolicy` (`:1925-2023`), deprecation notes (`:2179-2304`). Explicit path wins over `<state-dir>/policy.yaml`. |
| `--policy-pubkey` | `:253` | `loadGuardSigningKeys` (`:1275-1297`), policy verification in `loadPolicyForRun` (`:1582-1624`), pin verification in `loadPins` (`:4295-4337`), audit/start event does not log the key path. |
| `--policy-key` | `:254` | `loadGuardSigningKeys` (`:1275-1297`), pin signing in `savePins` (`:4340-4394`), and policy verification with the derived public key. Never logged. |
| `--readonly` | `:255` | `applyPolicy` (`:1960-1964`) sets `readonly` and `readonlyOverride`; `classFor` returns `read` (`:4860-4868`); `fromHost` forwards read-class calls before hard blocks (`:3973-3977`). Replaces policy/profile read entries when explicitly set. |
| `--trust` | `:256` | `applyPolicy` (`:1965-1969`); `fromServer` skips taint and datamarking for trusted `tools/call` results (`:4151-4153`). Replaces policy trust entries when explicitly set. |
| `--approve` | `:257` | Validated when explicitly set (`:440-443`); `applyPolicy` (`:1942-1953`); protected-target handling (`:4006`); dialog branch (`:4041-4054`); `askHuman` (`:5431-5482`); default deny (`:4055-4057`). |
| `--no-spotlight` | `:258` | `applyPolicy` (`:1946-1956`) sets `spotlight`; `fromServer` skips `datamark` for tool results (`:4155-4157`); `datamark` (`:4193-4239`). Note this also skips invisible-character stripping, not only the wrapper. |
| `--reset-pins` | `:259` | `loadPins` (`:296`, `:4295-4299`): removes the pin file and its signature, logs `pins_reset`, then repins on the next `tools/list`. |
| `--allow-write-under` | `:261` | Repeatable `stringList`; parsed into `scratchRule` (`:445-459`), canonicalized at startup; `applyPolicy` (`:1971-1975`); scratch branch (`:4036-4040`); `scratchAllows` (`:5412-5424`); `protectedCall` checks relative names (`:4661-4667`); `start` event logs the raw specs (`:317-320`). |
| `--grant` | `:263` | Repeatable `stringList`; parsed into seeded grants (`:460-483`); stored in `Guard.grants` (`:515`); `grantAllows` (`:4031-4035`, `:5383-5407`); protected calls require a human grant (`:5394`); dialog grant recording (`:4045-4048`). |

### 9.2 Subcommand flags

| Command | Flag | Parsed at | What it reaches |
|---|---|---|---|
| `install` | `--yes` | `:8106` | Skips confirmation before config/policy writes (`:8194-8235`). |
| `install` | `--dry-run` | `:8107` | Shows config diff without writing; skips policy/allowlist update (`:8159-8190`, `:8194-8235`). |
| `install` | `--policy` | `:8111` | `policyWritePath` / `writePolicyFile` (`:8159-8189`, `:8215-8235`, `:3236-3248`, `:3332-3351`), and pinned into the wrapper (`:8136-8154`). |
| `install` | `--state-dir` | `:8112` | Default policy location and pinned into the wrapper (`:8136-8154`, `:8159-8164`). |
| `uninstall` | `--yes`, `--dry-run` | `:8106-8107` | Same `runConfigCommand` path, `action == "uninstall"` (`:8194-8214`). |
| `allow` | `--policy` | `:2550` | `policyWritePath` (`:2599`), `loadPolicyForUpdate` (`:2617`), `writePolicyFile` (`:2630`). |
| `allow` | `--state-dir` | `:2551` | Default policy location (`:2599`). |
| `allow` | `--yes` | `:2552` | Skips the confirmation prompt (`:2608-2616`). |
| `policy` | none | `:2306-2349` | Positional `validate <file>`, `sign`, `verify` or `print-default`. |
| `keys` | `init --out`, `--key`, `--force`, `--state-dir` | `:1395-1494` | Generates the Ed25519 keypair; refuses a private key inside the state dir; warns that the private key can loosen Guard. |
| `pins` | `sign/verify --name`, `--state-dir`, `--key`, `--pubkey` | `:1496-1580` | Signs or verifies `pins-<name>.json` with a detached `.sig`. |
| `doctor` | `--json` | `:6795` | JSON report instead of human text (`:6060-6066`). |
| `doctor` | `--policy` | `:6796` | Explicit policy for the audit (`:6052-6054`, `:6083-6086`). |
| `doctor` | `--state-dir` | `:6797` | Default state dir when a wrapper does not pin one (`:6054`). |
| `doctor` | `--require-signatures` | `:6798` | Reports unverified policy/pins as findings (`:7155-7188`). |
| `clear-taint` | `--name` | `:6289` | Session name; required (`:6301-6304`); control lookup (`:6319`). |
| `clear-taint` | `--state-dir` | `:6290` | State dir, default `~/.sylenix-poc` (`:6309-6318`). |
| `stats` | `--name` | `:6456` | Reads `<state-dir>/audit-<name>.jsonl` (`:6483-6495`). |
| `stats` | `--file` | `:6457` | Reads the named audit log directly (`:6483`). |
| `stats` | `--state-dir` | `:6458` | Only valid with `--name` (`:6475-6478`). |

Flag/policy precedence in `applyPolicy` (`:1925-2023`): `--approve` overrides
`approval`, `--no-spotlight` overrides `spotlight`, `--readonly` replaces policy
and profile read classes, `--trust` replaces policy trust, and
`--allow-write-under` replaces policy `allow_paths`. `--grant` is flag-only.

## 10. State on disk

Default state directory: `~/.sylenix-poc` (`:497-504`). It is created with
`0700`, but an existing directory is not chmod-ed.

| File | Format | Mode | Lifecycle / code |
|---|---|---|---|
| `audit-<name>.jsonl` | One JSON object per line. Base fields: `ts` (RFC3339Nano UTC), `server`, `event`; event-specific fields include `tool`, `rule`, `arg_keys`, `origin`, `class`, `granted`, `scope`, `source`, `version`, `profile`, `command`. Never argument values. | `0600` on create | Opened append-only at startup (`:507`); written by `event` (`:5875-5884`); no rotation or fsync. |
| `pins-<name>.json` | Indented JSON object: tool name -> 64-character hex SHA-256 of the JSON-marshaled tool definition. | `0600` | `pinsPath` (`:4290`); `loadPins` (`:4295-4338`); `savePins` (`:4340-4394`); atomic temp+rename. |
| `pins-<name>.json.sig` | Raw 64-byte Ed25519 signature over the exact pin-file bytes. | `0600` | Written by `savePins` when `--policy-key` is set (`:4340-4394`); verified by `loadPins` when a public key is configured (`:4295-4338`); removed by `--reset-pins`. |
| `policy.yaml` | Version-1 YAML (strict subset) or JSON. Schema: version, profile, approval, spotlight, sensitive_paths, egress allow/deny hosts, allowlist, servers/tools. | `0600` when written by Guard | Auto-loaded from state dir or `--policy` (`:1582-1624`); strict parse/validation (`:1681-1855`); canonical write drops comments and stale signatures (`:3155-3234`, `:3332-3354`). |
| `policy.yaml.sig` | Raw 64-byte Ed25519 signature over the exact policy bytes. | `0600` | Written by `policy sign` (`:2198-2247`); verified at startup (`:1582-1624`); removed by `install`/`allow` rewrites. |
| `~/.sylenix-keys/policy-signing.key` | PKCS#8 PEM Ed25519 private key. | `0600` | `keys init` default path, outside the state dir (`:1395-1494`); never read by `doctor`. |
| `~/.sylenix-keys/policy-signing.key.pub` | PKIX PEM Ed25519 public key. | `0600` | Written by `keys init`; pass with `--policy-pubkey`. |
| `control-<hash>.json` | JSON `{version,name,pid,nonce,started_at,heartbeat}`. `<hash>` is the first 16 bytes of SHA-256(name), hex. | `0600` | Created by `startGuardControl` (`:6047-6068`); heartbeat every 2 s (`:6075-6086`); stale after 15 s (`:6374-6405`); removed on exit (`:6254-6272`). |
| `clear-taint-request-<hash>.json` | JSON `{version,nonce,guard_started,request_id,requested_at}`. | `0600` | Written by CLI (`:6329-6340`); polled and removed by guard (`:6120-6160`); TTL 2 min. |
| `clear-taint-result-<hash>-<request_id>.json` | JSON `{version,request_id,status,who,at,note}`. | `0600` | Written by guard (`:6233-6241`); read and removed by CLI (`:6407-6437`); stale results removed at next guard start (`:6243-6252`). |
| `<config>.sylenix-backup-<UTC timestamp>` | Byte-for-byte copy of an MCP client config before `install`/`uninstall`. | Original file mode | `writeConfigBackup` (`:8787-8805`). |
| `policy.yaml` written by `install`/`allow` | Canonical YAML; comments/formatting not preserved. | `0600` | `writePolicyFile` (`:3332-3344`). |

No tokens or auth headers are stored. The HTTP proxy keeps only the configured
upstream URL and an in-memory HTTP client; `Mcp-Session-Id` is passed through and
never written to disk. The audit log records tool names, argument key names,
paths/scope values, and command paths, but not argument values or header values
(`event`, `:5875-5884`; also `POC_SPIKE.md:99`).

## 11. What `make check` runs

`make check` is the aggregate target at `Makefile:50`:

```text
check: fmt vet selftest probe-test proxy-test signing-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test
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
6. **`signing-test`** (`Makefile:29-30`): `tests/probes/test_signing.py`, key
   generation, policy/pin signing, tamper detection and unsigned-file rejection.
7. **`profile-test`** (`Makefile:32-33`): `test_profiles.py` for the built-in
   filesystem, git, GitHub, fetch, shell, Slack, Postgres, browser, Notion, and
   Jira profiles.
8. **`replay-test`** (`Makefile:35-36`): `scripts/replay_profile_session.py`,
   which reports approval prompts per active hour for the recorded filesystem
   session.
9. **`summary-test`** (`Makefile:38-39`): runs `scripts/summarize_audit.py` on
   `demo/fixtures/audit_sample.jsonl`, strips CRs with `tr`, and diffs against
   `demo/fixtures/audit_sample.expected.txt`.
10. **`doctor-test`** (`Makefile:41-42`): `tests/probes/test_doctor.py`.
11. **`clear-taint-test`** (`Makefile:44-45`):
    `tests/probes/test_clear_taint.py`.
12. **`stats-test`** (`Makefile:47-48`): `tests/probes/test_stats.py`.

`make check` does **not** run `go test ./...` (there are no Go tests), and does
not run the agent harness or sweep. The harness is a separate target:
`make harness-scripted` (`Makefile:54-55`) uses
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
   `main.go:1063-1073`) and never logged or persisted.
2. **Taint is per guard process and per wrapped server.** It does not cover
   host built-in tools, attachments, or pasted text, and restarting the guard
   starts a clean session (`POC_SPIKE.md:233-236`; `main.go:512-515`). This is
   fundamental to the current design.
3. **No confidentiality latch.** Reading a secret and then calling a read-only
   tool is not tracked (`POC_SPIKE.md:238`).
4. **The HTTP proxy does not enforce the server-command allowlist.** The
   allowlist is a launch control for a child process (`checkServerAllowed`,
   `main.go:2127-2177`); `proxy` has no child command and skips it. A policy with
   `allowlist_enforced: true` therefore does not restrict `--upstream`.
5. **SSE resumability is left to the client and upstream.** The proxy forwards
   `Last-Event-ID` and SSE event IDs, but keeps no replay buffer and does not
   persist streams (`copyRequestHeaders`, `main.go:1063-1073`; `streamSSE`,
   `:1133-1216`). A broken connection loses in-flight events unless the upstream
   can replay them. This matches the 2026-07-28 direction, which removes
   resumability, but is a real gap for 2025-11-25 servers that expect the client
   to resume.
6. **Auth-header pass-through is broad by design.** Every end-to-end request
   header except the explicit hop-by-hop/Host/Content-Length/Origin set is
   copied upstream (`copyRequestHeaders`, `main.go:1063-1073`). That includes
   `Authorization`, `Cookie`, `X-Api-Key` and any custom auth header the client
   sends. The guard does not validate the credential, scope it to a host, or
   replace it. Only the configured `--upstream` sees it.
7. **The HTTP listener is loopback-only by default, but `--listen` can expose
   it.** `normalizeListenAddr` maps an empty host or `localhost` to
   `127.0.0.1` (`main.go:753-767`), but an explicit `0.0.0.0` or LAN address is
   accepted. The listener itself is plain HTTP; use a loopback address or a
   trusted tunnel/reverse proxy for anything else. Origin checking is not a
   substitute for authentication (`originAllowed`, `:843-864`).
8. **Session IDs are passed through, not mapped per client.** A client that
   presents another client's `Mcp-Session-Id` is forwarded with that ID; the
   proxy adds no session isolation of its own (`copyRequestHeaders`,
   `main.go:1063-1073`). The upstream is responsible for authenticating the
   session, as it would be without the proxy.

### Enforcement gaps that are easy to trip over

9. **`--readonly` / `class: read` bypasses every sink check, including
   `EGRESS_TARGET` and `SENSITIVE_TARGET`.** The read check is before the hard
   blocks (`main.go:3972-3977`), and `classFor` returns `read` for anything on
   the list (`:4860-4868`). `POC_SPIKE.md:233` calls this a trust decision. A
   mis-listed tool defeats the latch.
10. **`--trust` suppresses taint and datamarking for that tool's results.**
   `fromServer` returns early for trusted `tools/call` results (`main.go:4151-4153`).
   Trust only applies to `tools/call`, not `resources/read` or `prompts/get`.
11. **`--no-spotlight` disables more than the wrapper.** It skips the entire
   `datamark` call (`main.go:4155-4157`), so invisible-character stripping and
   `structuredContent` cleanup are skipped too. The flag help says only "do not
   datamark" (`:252`), and `POC_SPIKE.md:190` says "Skip datamarking".
12. **Argument classification is a heuristic.** Only known path keys are treated
   as paths; a path under a content-named key is ignored (`main.go:4712-4713`),
   and an unknown-shaped value can be classified as ambiguous or not path-like
   at all (`:4757-4760`, `looksLikePath` `:4963-4975`). A tool-wide `--grant`
   can therefore cover calls whose path the guard did not recognize. This is
   acknowledged in `POC_SPIKE.md:243`.
13. **Pinning is trust on first use and does not sanitize the first
   definition.** A first `tools/list` can contain prompt-injected tool
   descriptions; the guard pins them rather than rejecting them
   (`main.go:4243-4283`, `POC_SPIKE.md:239`). Pin files are signed only when
   `--policy-key`/`--policy-pubkey` enables signing; otherwise they remain
   same-user writable, and signing detects modification rather than rollback.
14. **A later identical `tools/list` un-quarantines a tool.** `inspectToolsList`
   deletes the quarantine entry when the definition matches the old pin
   (`main.go:4277`). That is probably intended recovery, but it means a server
   that alternates between two definitions moves the tool in and out of
   quarantine; calls are blocked only during the quarantined period.
15. **`tools/list` pinning is skipped silently if the result shape is not the
    expected `{tools: [...]}`.** `inspectToolsList` returns without error on
    unmarshal failure (`main.go:4247-4249`), so no pins and no quarantine are
    recorded for that response.
16. **The guard does not reject duplicate keys in server frames.** Host frames
    get the `hasDuplicateKeys` check (`main.go:3929-3932`), but `fromServer`
    decodes with plain `json.Unmarshal` (`:4117`) and never checks duplicates.
    A malicious server can present one value to the guard and another to a
    host whose JSON parser resolves duplicates differently. The same issue
    exists inside tool definitions and policy JSON only insofar as the guard
    decodes them.
17. **Datamarking is structural, not a real content boundary.** It only wraps
    `content[].text` and only neutralizes the exact lower-case
    `</untrusted_tool_result` string (`main.go:4210`). Case variants, unusual
    result shapes, resource/prompt results, and non-text content are not
    wrapped (`:4146-4157`, `:4194-4201`). `POC_SPIKE.md:240` acknowledges that
    spotlighting is friction, not protection.

### Path, egress, and approval risks

18. **Sensitive/egress checks are textual and path-based, not a sandbox.**
    Egress matching compares host strings and does not resolve DNS, follow
    redirects, or pin IPs (`main.go:4870-4961`, `POC_SPIKE.md:250`). Scratch
    path checks resolve symlinks but leave a check-to-write race
    (`main.go:5296-5320`, `POC_SPIKE.md:244`).
19. **A directory-scoped grant is broader than one call.** `addGrant` records
    tool plus directory; `grantAllows` allows any call to that tool whose paths
    stay inside the directory for 15 minutes (`main.go:5373-5407`). A human
    approval for one protected file can therefore cover other protected files
    in the same directory while the grant is live (`:5394`). `POC_SPIKE.md:242`
    documents the broader grant scope.
20. **Dialog mode blocks the calling transport while a dialog is open.**
    `askHuman` runs synchronously in the stdio host-to-server goroutine
    (`main.go:4041-4044`, `:5431-5482`; `POC_SPIKE.md:241`). In stdio mode that
    stalls the whole session; in HTTP mode only that request's handler waits,
    but concurrent requests can each open a dialog. A slow or stuck dialog
    stalls the call for up to 60 seconds.
21. **Dialog text is truncated and sanitized, not a trustworthy rendering of
    the call.** Arguments are cut at 300 characters and control/invisible
    characters are removed (`cleanForDialog`, `:5622-5639`; `askHuman`,
    `:5431-5434`). Confusable or long arguments can still mislead a human.

### State, audit, and local-process risks

22. **`--name` is validated at startup, but `stats --name` still concatenates
    an unvalidated name.** `prepareGuard` now uses `validDoctorName`
    (`main.go:492`, `:7725-7736`), so the proxy and stdio paths reject path
    separators. `stats --name` still builds `audit-<name>.jsonl` directly
    (`:6495`), so a caller can read another `.jsonl` path relative to the state
    directory. Use a simple name and a unique state directory.
23. **Audit and pin write errors are ignored.** `event` discards the
    `log.Write` result (`main.go:5881-5883`), and `savePins` discards both the
    temp-file and rename errors (`:4340-4394`). A full or read-only state
    directory can silently lose audit records or pins while the proxy keeps
    running. There is no fsync or rotation.
24. **Existing state-dir and audit-file permissions are not tightened.**
    `MkdirAll(..., 0700)` and `OpenFile(..., 0600)` only set modes on creation
    (`main.go:504-509`); an existing `0755` directory or `0644` audit file stays
    that way.
25. **Clear-taint control files are same-user state, not authentication.**
    A same-user process, including the wrapped server, can request a dialog
    (`main.go:6047-6272`; `POC_SPIKE.md:235`). Only a human click clears the
    latch, but the dialog is local and not biometric. A successful clear does
    not revoke grants or quarantines (`:4186-4191`).
26. **Two guards using the same `--name` and state dir share pins, audit, and
    control paths.** The control path is keyed by a hash of the name
    (`main.go:5980-5995`), and `cleanupStaleFiles` removes request/result files
    for that name at startup (`:6243-6252`). Use a unique name per guard;
    `POC_SPIKE.md:235` makes the same point for clear-taint.
27. **`install` and `allow` persist and print server arguments.** The allowlist
    is an exact command/args record (`main.go:93-99`, `:2137-2145`), and
    `allow`/`install` print the arguments to the terminal
    (`:2604-2607`, `:8218-8222`) before writing them to `policy.yaml`. If a
    server passes a token in an argument, it can end up in the policy file and
    terminal scrollback. The audit log itself does not record argument values.
28. **The server's stderr is inherited, not mediated.** `cmd.Stderr = os.Stderr`
    (`main.go:312`) means a server can write directly to the operator's terminal,
    including escape sequences or secrets, without the guard inspecting it.
29. **The pending-request map never expires.** `track` adds ids and only
    `take`/`failPending` remove them (`main.go:5807-5860`); a server that never
    answers an id leaves an entry for the life of the process
    (`POC_SPIKE.md:253`).
30. **Signal cleanup is minimal.** The signal goroutine stops control, kills the
    child, and exits (`main.go:327-334`); descendants of a wrapper such as
    `npx` are not killed (`POC_SPIKE.md:252`).

### Build, test, and configuration clarity

31. **`make check` is POSIX-shell dependent on Windows.** `fmt` uses `test`
    (`Makefile:9-10`), and `summary-test` uses `tr` and `diff`
    (`Makefile:38-39`); `README.md:121-122` says Git Bash or WSL is required.
    `make harness-scripted` also hard-codes `.venv/bin/python`
    (`Makefile:52-53`), which is not a Windows path.
32. **There are no Go unit tests.** `make check` runs `go vet` and Python
    integration probes, but not `go test ./...` (`Makefile:50`). A regression
    in an unexercised helper can pass the suite.
33. **Policy loading is one-shot; signing is optional.** The file is read at
    startup and not watched (`main.go:532-549`; `POC_SPIKE.md:247`). When a
    public key is configured, the exact bytes must have a valid `.sig` or the
    guard exits 2 before parsing (`loadPolicyForRun`, `:1582-1624`). Without
    `--policy-pubkey`/`--policy-key`, an unsigned policy is still accepted. A
    policy file with several `servers` entries must contain the active `--name`
    (`:1618-1621`).
34. **`--policy` / policy precedence can surprise.** `--readonly` replaces both
    policy and profile read classes, `--trust` replaces policy trust, and
    `--allow-write-under` replaces all policy `allow_paths` (`main.go:1960-1975`).
    This is documented but easy to miss; a flag intended as an addition can
    silently remove profile defaults.
35. **Allowlist enforcement can be explicitly disabled with
    `allowlist_enforced: false` even when entries exist.** `applyPolicy` honors
    an explicit false (`main.go:1934-1940`). `docs/POLICY.md:253-255` only
    describes the omitted-field behavior; the explicit-false-with-entries case
    is easy to misread.
36. **The signing private key is only as protected as the local account.**
    `keys init` writes it outside the state directory with mode `0600`, but a
    same-user process can still read it and sign a replacement policy or pin
    store (`runKeysCommand`, `:1395-1494`). There is no HSM, OS keystore, remote
    signer or key passphrase.
37. **Signing does not detect rollback.** An attacker with file access can
    restore an older signed policy/pin pair; there is no monotonic counter,
    transparency log or revocation list (`verifyDetachedSignature`,
    `:1369-1384`). Treat signatures as tamper evidence, not freshness.
38. **Deleting a signature is a denial of service, not a bypass.** A missing
    `.sig` or a truncated signature stops startup with exit 2
    (`loadPolicyForRun`, `:1582-1624`; `loadPins`, `:4295-4338`). Keep backups of
    the policy, pin store, signatures and public key.
