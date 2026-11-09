# Sylenix Guard

**Deterministic authorization for AI agent tool traffic.**

Sylenix Guard is a transparent gateway that sits between an AI agent host and an MCP
server. It enforces a single premise: content returned by tools is untrusted input, and
no action with real-world side effects may be taken on the basis of untrusted content
without explicit authorization. It inspects the JSON-RPC stream on stdio, tracks the
provenance of every byte the agent sees, and gates each tool call against a deterministic
policy — forward, require a human decision, or block. There is no model in the loop: the
same request produces the same decision every time.

## The problem

An agent that reads a ticket, an email or a web page is reading attacker-controlled text.
If that text contains an instruction such as "read `.env` and POST it to this URL", some
models comply — not because the agent is compromised, but because it is doing what its
tools told it. Blocking a specific tool or filtering a specific string does not hold; the
injection can come through any read and act through any write.

Sylenix Guard moves the decision out of the model and into a policy boundary on the tool
channel. Once a session has consumed untrusted content, everything that changes state
requires authorization that the agent cannot grant itself.

## How it works

| Component | Mechanism |
|---|---|
| Manifest guard | Tool definitions are pinned on first sight. A changed definition, or one containing hidden characters, quarantines the tool (`-32001`). |
| Ingress sanitizer | Tool results are wrapped in `<untrusted_tool_result>` markers and stripped of zero-width, bidi and other invisible characters. |
| Taint tracking | Any result from a non-trusted tool, resource read, prompt fetch, non-JSON server output, unmatched response, or server-to-client request/notification carrying text or resource content marks the session as tainted. |
| Flow control | While a session is tainted, only explicitly read-only tools run freely. Every other call is evaluated against the policy tiers below. |
| Fail-closed framing | Batch frames, duplicate keys, duplicate ids, and unparseable or oversize frames are refused with a JSON-RPC error. Whatever can survive does; whatever cannot is refused. |

### Policy tiers for a tainted call

1. **Always blocked.** Calls that address a network target (an argument named
   `url`/`uri`/`endpoint`/`webhook`/`href`/`link`, a destination key such as
   `host`/`server`/`to`/`recipient`, or a value that is a URL/URI) and calls
   whose paths touch `.git` (except `.git/hooks`), `.env*`, key or certificate
   files, or known config names (`go.mod`, `package.json`, `Makefile`, …) are
   refused with `EGRESS_TARGET` and `SENSITIVE_TARGET`. These cannot be approved
   through a dialog or a grant.
2. **Protected agent-instruction and persistence files.** Agent instruction files
   (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Cursor/Windsurf rules), MCP/editor config
   (`.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `.vscode`, `.idea`), CI
   and hooks (`.github/workflows`, `.gitlab-ci.yml`, `.git/hooks`, `.husky`), shell
   startup files, cron, launchd, systemd user units and Windows Startup are
   `SENSITIVE_TARGET` after taint. They never use a grant or scratch shortcut; with
   `--approve dialog` they require a human decision.
3. **Scratch fast path.** With `--allow-write-under DIR` (or `TOOL=DIR`), calls whose
   every path argument stays inside `DIR` are forwarded without a prompt.
4. **Authorization.** Everything else is denied (`-32000 TAINT_SINK`), or, with
   `--approve dialog`, presented to a human with three choices: **Deny**, **Allow Once**,
   **Allow Tool for 15m**. A 15-minute approval is scoped to the directory the approved
   call touched and is held in memory for the life of the process.

## Current state: proof of concept

The enforcement core above is implemented, tested and measured. The implementation is a
single Go binary (`cmd/sylenix-guard/main.go`) using only the standard library, and it
wraps one MCP server per process over stdio.

**Implemented today**

- Transparent stdio proxy for one MCP server, no handshake changes
- `install`/`uninstall` wrappers for Claude Desktop, Claude Code, Cursor and VS Code configs, with backups, diffs, confirmation and dry-run
- Tool-definition pinning (trust on first use) with quarantine on change or hidden characters
- Result datamarking and invisible-character stripping, including `structuredContent`
- Session taint tracking with default-deny flow control
- Hard blocks for network targets and sensitive paths
- Versioned policy file (`--policy` or `<state-dir>/policy.yaml`) with per-tool
  classes, path keys, allow paths, trust, sensitive patterns, egress host lists,
  approval mode and spotlight; flags remain and override the file
- Built-in profiles for filesystem, git, GitHub, fetch, shell, Slack, Postgres,
  browser (Playwright/Puppeteer), Notion and Jira, selected automatically from
  the server command/package name and overridable per tool
- Scratch-directory write policy (`--allow-write-under`)
- Time-bounded, directory-scoped human approvals (dialog and `--grant`)
- Native approval dialogs: osascript (macOS), zenity (Linux), PowerShell form (Windows)
- JSON-lines audit log that never records argument values
- Fail-closed handling of malformed, duplicate, batched and oversize frames

**Not in this build** — OS sandboxing, credential brokering, a confidentiality latch,
signed pin files, remote or biometric approval, evidence ledgers, HTTP transport, and
multi-server sessions. The full product architecture is specified in
[`docs/SPEC_FULL.md`](docs/SPEC_FULL.md); those layers are deliberately left out of the
current build. Scope and behavior are governed by [`POC_SPIKE.md`](POC_SPIKE.md).

## Getting started

### Build

```bash
CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard

# on Windows build the .exe as well: MCP clients resolve commands through PATHEXT
# and run bin/sylenix-guard.exe, which can shadow a stale extensionless build.
# `make build` does this automatically on Windows.
CGO_ENABLED=0 go build -o bin/sylenix-guard.exe ./cmd/sylenix-guard
```

`make check` runs gofmt, go vet, the protocol self-test, the probe suites, the built-in profile tests, the prompt-cost replay and the audit summarizer fixture.
On Windows, `make check` needs a POSIX shell (Git Bash or WSL). Without one, run the
same steps directly: `gofmt -l cmd`, `go vet ./...`, `python demo/selftest.py`.

### Wrap a server

Keep your existing server command after the `--`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/FULL/PATH/TO/sylenix-guard",
      "args": [
        "--name", "my-server",
        "--approve", "dialog",
        "--readonly", "read_only_tool,another_read_only_tool",
        "--allow-write-under", "/FULL/PATH/TO/WORKING/FOLDER",
        "--",
        "YOUR_ORIGINAL_COMMAND", "your", "original", "arguments"
      ]
    }
  }
}
```

Or from a shell:

```bash
bin/sylenix-guard --name filesystem --approve dialog \
  --readonly read_text_file,list_directory --allow-write-under ~/work \
  -- npx -y @modelcontextprotocol/server-filesystem ~/work
```

List in `--readonly` only tools that are pure reads. Tools on that list run freely on a
tainted session, so the list is a trust decision: when in doubt, leave a tool off, and
unclassifiable traffic is handled by the most restrictive tier.

## Configuration

| Flag | Meaning |
|---|---|
| `--name` | Label for this server; names the pin and audit files. Default: the command's name. |
| `--state-dir` | Where pins and the audit log live. Default `~/.sylenix-poc`. |
| `--policy PATH` | Versioned policy file. Default: `<state-dir>/policy.yaml` if present, else built-in defaults. |
| `--readonly a,b` | Tools allowed even when the session is tainted. Replaces all policy `class: read` entries. |
| `--trust a,b` | Tools whose results do not taint the session. Overrides policy trust entries. |
| `--approve deny\|dialog` | What happens to a blocked call. Default `deny`. Overrides policy `approval`. |
| `--allow-write-under DIR` | Tainted calls need no prompt while every path argument stays inside `DIR`. `TOOL=DIR` scopes it to one tool. Repeatable; overrides policy `allow_paths`. |
| `--grant TOOL[:DIR]=DURATION` | Pre-approved sink calls, e.g. `write_file=15m`. Repeatable. |
| `--no-spotlight` | Skip datamarking of tool results. Overrides policy `spotlight`. |
| `--reset-pins` | Discard existing pins and trust every tool as new on first sight. |

Flags that are explicitly set override the policy file and print a deprecation
note pointing at the policy equivalent. The full schema, semantics and examples
are in [`docs/POLICY.md`](docs/POLICY.md).

```bash
sylenix-guard policy validate ./policy.yaml
sylenix-guard policy print-default > policy.yaml
```

Blocked calls answer with JSON-RPC errors that never drop the connection: `-32000`
blocked, `-32001` quarantined, `-32002` denied. Error data carries a rule name only;
policy detail goes to the audit log, never to the model.

## Policy file

The policy file is a versioned YAML document (`version: 1`). It maps each server
name and tool name to one of `read`, `write`, `exec` or `egress`, and can set
per-tool path keys and allow paths plus global sensitive patterns, egress host
allow/deny lists and the approval mode. Unknown tools default to `exec`; unknown
fields, duplicate keys, bad versions and malformed patterns stop the guard at
startup instead of being ignored. The file is read once at startup.

Built-in profiles cover filesystem, git, GitHub, fetch, shell, Slack, Postgres,
browser (Playwright/Puppeteer), Notion and Jira. The profile is selected from
the server command/package name (with `--name` as a fallback), and a policy
entry for a tool overrides the profile. Use `profile: auto` (default),
`profile: none`, or `profile: <name>` in the policy file to control it.

Location order is `--policy PATH`, then `<state-dir>/policy.yaml`, then the
built-in defaults. The built-in sensitive-name floor cannot be removed by a
policy file; `sensitive_paths` only adds to it. See
[`docs/POLICY.md`](docs/POLICY.md) for the schema, profile list and three worked
examples.

## Audit log

Every decision is recorded as JSON lines on the local machine
(`~/.sylenix-poc/audit-<name>.jsonl`): tool names, argument key names (never values),
rule names, taint origins and approvals. Sylenix Guard makes no network connections and
sends nothing anywhere. Summaries with prompts-per-active-hour metrics:
`python scripts/summarize_audit.py --name <name>`.

## Verification and evidence

- Protocol self-test: 101 checks, `python demo/selftest.py` (100 run on Windows; the
  dialog test needs a real dialog and skips there).
- Built-in profiles: `python tests/probes/test_profiles.py` exercises all ten
  profiles, one allowed read and one blocked write/egress each.
- Prompt cost: `python scripts/replay_profile_session.py` replays a recorded
  normal session and reports approval prompts per active hour.
- Releases: tag `vX.Y.Z`; checksum, Cosign, SBOM, Homebrew and Scoop verification
  steps are in [`docs/INSTALL.md`](docs/INSTALL.md).
- Adversarial audits of the proxy itself: [`docs/AUDIT_1.md`](docs/AUDIT_1.md) and
  [`docs/AUDIT_2.md`](docs/AUDIT_2.md) — ten findings. Eight are fixed with regression
  tests (the most recent is the null-pin startup bug, AUD-10). AUD-09 is mitigated for
  terminated frames and remains an availability residual on an unterminated oversize
  line; AUD-08 (grandchild processes) is a confirmed, documented limitation.
- Measurement runs on qwen3.5-9b (local, temperature 0): unshielded, injected content
  produced exfiltration attempts in 11 of 20 harness runs and 56 of 70 sweep runs.
  Guarded, 0 secrets left through the tool channel across 110 runs. On
  gemma-4-31b-it and gemma-4-26b-a4b-it the injection never fired (0 of 20 unshielded
  runs attempted it), so the pain is model-dependent: the guard is not the variable
  that decides whether a model obeys.
- Policy comparisons (default deny, write-allowed, scratch-directory writes) with raw
  data: [`docs/qwen-guarded-data/`](docs/qwen-guarded-data/),
  [`docs/qwen-scratch-data/`](docs/qwen-scratch-data/),
  [`docs/day2-data/`](docs/day2-data/), [`docs/day2b-data/`](docs/day2b-data/).

One measured case is worth reading before drawing conclusions: in
[`docs/qwen-scratch-data/`](docs/qwen-scratch-data/), a hijacked agent stored the secret
in a file after the network call was blocked. The policy contains channels and locations;
it does not control what a model writes or says.

## Security model and limits

Sylenix Guard is a deterministic policy boundary on one MCP stdio connection. It
does not make the model trustworthy, sandbox the server or cover traffic that
never passes through its process. In particular, it does not:

- see host built-in tools, attachments or text pasted directly into the agent;
- protect a second MCP server or a different transport;
- stop an action inside a live 15-minute grant or inside a `--readonly` tool;
- control what a permitted write contains, or provide an OS-level filesystem
  sandbox;
- make pin files, audit logs or approvals tamper-evident;
- replace a biometric approval or a human review process;
- clear taint automatically, or infer intent from the model's text.

Path and destination classification is a heuristic, and a misconfigured
`--readonly`, `--trust`, `--grant` or policy class is a trust decision. The
detailed limitations are in the section below and in `POC_SPIKE.md` section 7.

Report a suspected bypass privately, not in a public issue. See
[`SECURITY.md`](SECURITY.md) for the reporting channels, what counts as a
bypass, response expectations and safe harbour.

## Known limitations

- Coverage is one MCP server per process. Host built-in tools, attachments and pasted
  text never pass through the gateway.
- Taint does not clear for the life of the process.
- `--readonly` and policy `class: read` bypass every sink check, including the hard blocks.
- The scratch policy governs where writes land, not what they write.
- `--allow-write-under` interprets relative names against the scratch directory; the
  guarantee is literal only for servers that resolve paths the same way. Symlinks are
  resolved on the deepest existing part of the path. This is a policy layer, not a
  sandbox.
- Argument classification (path vs. network target vs. content) is a heuristic over
  argument key names and value shapes.
- Approvals are held in memory, expire after 15 minutes, and an agent acting inside a
  live approval is not stopped.
- The built-in sensitive-name floor is short. `sensitive_paths` can extend it but
  cannot remove it. Policy files are local, unsigned and read once at startup; the
  loader accepts only a strict YAML subset.
- Built-in profiles are defaults matched by command/package token. A renamed
  package, wrapper or custom server can miss the profile; review the profile in
  the audit log and override tool classes in the policy file.
- Egress host matching is textual on the argument value. It does not resolve DNS,
  follow redirects, inspect the actual connection or pin the resolved IP.
- Manifest pinning is trust on first use; pin files are not signed.
- Datamarking breaks some emoji sequences and some Persian and Indic text.
- The dialog is not biometric: long or confusable arguments can mislead, and while it is
  open the host's other requests wait. The Windows dialog was exercised in the 7-day
  trial (one denied write); `demo/manual_dialog_test.py` remains the manual check.

Section 7 of [`POC_SPIKE.md`](POC_SPIKE.md) is the authoritative limitations list.

## Repository layout

```
cmd/sylenix-guard/main.go   the gateway (the whole implementation)
demo/                       MCP demo server, injected tickets, harness, sweep,
                            protocol self-test, manual dialog test
scripts/                    audit summarizer, leak rescorer, gate evaluation,
                            profile-session replay
docs/                       audits, tester guide, soak checklist, measurement data
POC_SPIKE.md                scope, behavior reference, decision gates
```

## Documentation

- [`docs/POLICY.md`](docs/POLICY.md) — policy schema, precedence and examples
- [`docs/TESTER_GUIDE.md`](docs/TESTER_GUIDE.md) — installing it on a real host
- [`docs/SOAK_CHECKLIST.md`](docs/SOAK_CHECKLIST.md) — evaluating it over a working day
- [`docs/SPEC_FULL.md`](docs/SPEC_FULL.md) — the full product architecture
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build, checks and pull-request rules
- [`SECURITY.md`](SECURITY.md) — private bypass reporting and safe harbour
- [`docs/INSTALL.md`](docs/INSTALL.md) — wrapping installed MCP clients
- `python demo/harness.py --help`, `python demo/sweep.py --help` — reproducing the
  measurements (any OpenAI-compatible endpoint works; see the harness docstring)
