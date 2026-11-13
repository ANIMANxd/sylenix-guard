# Policy file

Sylenix Guard can read one versioned policy file per run. It replaces the
repetitive `--readonly`, `--trust`, `--approve`, `--allow-write-under` and
`--no-spotlight` flags; the flags still work and override the file when set.

The paid-tier `--team-url` mode adds a signed team policy pulled over HTTPS. In
that mode the local file described here is an overlay that can only tighten the
team policy. See [`teams/README.md`](../teams/README.md) for the service, pull
cadence, cache, token model and merge rules.

## Where the file comes from

1. `--policy PATH`, if the flag is set.
2. `<state-dir>/policy.yaml`, if that file exists.
3. The built-in defaults.

An explicit or auto-loaded file that cannot be read or parsed is a startup
error (exit 2); the guard does not fall back to a weaker policy. If no file is
present, the built-in defaults apply. `--name` selects the server entry. When
`servers` is non-empty and `--name` is not set, a file with exactly one server
entry uses that entry; otherwise the requested name must exist in `servers`.

The file is read once at startup and is not watched. It can be signed with an
Ed25519 detached signature; see [Signing policy and pins](#signing-policy-and-pins).

## Signing policy and pins

Signing protects against an agent or local process changing `policy.yaml` or
`pins-<name>.json` while Guard is not looking. It is a file-integrity control,
not a sandbox: malware that can read the signing private key can produce a valid
signature.

### Create a keypair

```bash
sylenix-guard keys init
# private key: ~/.sylenix-keys/policy-signing.key
# public key:  ~/.sylenix-keys/policy-signing.key.pub

sylenix-guard keys init --out /secure/guard-keys
sylenix-guard keys init --key /secure/guard-keys/team.key --force
```

`--out DIR` creates `DIR/policy-signing.key` and `DIR/policy-signing.key.pub`;
`--key PATH` names the private key file explicitly. The private key is written
with mode `0600` outside the state directory (the default state directory is
`~/.sylenix-poc`). `keys init` refuses to place it inside the state directory and
prints a warning: anyone who can read the private key can loosen Guard. Keep it
off the agent machine or in a protected team store, and never commit it.

The private key is PKCS#8 PEM (`PRIVATE KEY`); the public key is PKIX PEM
(`PUBLIC KEY`). Raw 32-byte public keys and 32/64-byte private keys are also
accepted for tooling.

### Sign a policy

```bash
sylenix-guard policy sign --policy /path/to/policy.yaml --key /secure/guard-keys/policy-signing.key
sylenix-guard policy verify --policy /path/to/policy.yaml --pubkey /secure/guard-keys/policy-signing.key.pub
```

`policy sign` validates the policy first, then writes `policy.yaml.sig`: a raw
64-byte Ed25519 signature over the exact file bytes. `--policy` defaults to
`<state-dir>/policy.yaml`; `--key` defaults to
`~/.sylenix-keys/policy-signing.key`.

`install` and `allow` rewrite policy files canonically. They remove any old
`.sig` because it no longer matches; run `policy sign` again after those
commands.

### Verify at startup

```bash
sylenix-guard \
  --policy /path/to/policy.yaml \
  --policy-pubkey /secure/guard-keys/policy-signing.key.pub \
  --name filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem ~/work
```

- `--policy-pubkey PATH` verifies the policy and pin-store signatures. It is the
  team mode: put only the public key on the agent machine.
- `--policy-key PATH` loads the private key, derives its public key for
  verification, and signs new pin stores on write.
- If both are supplied they must match.
- When either flag is set, signing is enabled. An existing policy file must have
  a valid `.sig`, and an existing pin file must have a valid `.sig`; a missing,
  truncated, wrong-key or one-byte-changed signature stops Guard with exit 2
  before the policy is parsed or a tool is pinned.
- Built-in defaults need no signature because no policy file exists. A missing
  pin file still means genuine first sight.

`proxy` mode accepts the same two flags.

### Pins on write

With `--policy-key`, every pin-store write also writes `pins-<name>.json.sig`.
The pins are read back and verified before the tool list is accepted. With only
`--policy-pubkey`, Guard can verify an existing signed pin store but cannot sign
a new one; new pins stay in memory for that session and are not written
unsigned. To pre-sign or repair an existing store:

```bash
sylenix-guard pins sign --name filesystem --state-dir ~/.sylenix-poc --key /secure/guard-keys/policy-signing.key
sylenix-guard pins verify --name filesystem --state-dir ~/.sylenix-poc --pubkey /secure/guard-keys/policy-signing.key.pub
```

`--reset-pins` removes both the pin file and its signature. With a private key,
the replacement is signed on the next `tools/list`; without one, it stays
in-memory only.

Pins record the kind, name, description, SHA-256 and review state of every
pinned tool, resource, prompt and resource template. To inspect them and approve
each definition:

```bash
sylenix-guard pins review --name filesystem --state-dir ~/.sylenix-poc
```

The command prints each definition's name and full description and asks `y/N`
per item. Approved entries are written with `"reviewed": true`. If the pin file
is signed, pass `--policy-key` so the reviewed store is verified and re-signed;
without the key the command refuses to modify a signed store.

`doctor --require-signatures` reports a policy or pin file as `UNSIGNED_POLICY`
or `UNSIGNED_PINS` when no valid signature can be verified. If the wrapper has
`--policy-pubkey`, doctor verifies with that key.

### Limits

- The private key is only as safe as its file permissions and the machine
  account. Same-user malware that can read the key can sign a replacement; an
  HSM, OS keystore or remote signer is not implemented.
- Signing detects modification, not rollback. An attacker with file access can
  restore an older signed policy/pin pair. There is no monotonic counter,
  transparency log or revocation list.
- Deleting the signed policy file fails closed when signing is enabled. Deleting
  both the pin file and its signature is treated as genuine first use (TOFU) and
  lets the next `tools/list` re-pin; signing does not protect against that
  delete-to-TOFU path. Keep a backup, and treat a missing pin store as an
  incident.
- Signature files can be deleted, which causes a fail-closed startup; that is a
  denial of service, not a bypass. Keep a backup of the policy, pins, signatures
  and public key.
- Rotate by creating a new keypair, re-signing policy and pins, and replacing the
  public key in the wrapper. The old private key cannot sign for the new public
  key.

## Format

The loader accepts a strict YAML subset: block mappings, block sequences of
scalars, flow sequences/mappings, quoted and plain scalars, comments and one
leading `---`. JSON is also accepted. Anchors, tags, block scalars and multiple
documents are rejected; alias syntax is not resolved. Duplicate keys and unknown
fields are rejected. Unknown means the guard refuses to start, never that a
field is ignored.

```yaml
version: 1

# auto (default), none, or a built-in profile name
profile: auto

# deny (default) or dialog
approval: deny

# true (default) or false; false skips result datamarking
spotlight: true

# Extra glob patterns added to the built-in sensitive-name floor.
sensitive_paths:
  - "secrets/*"
  - "*.kdbx"

egress:
  # Host names, optionally with a leading *. wildcard. Deny wins over allow.
  allow_hosts:
    - "api.example.com"
    - "*.internal.example.com"
  deny_hosts:
    - "metadata.example.com"

# Require the server command and arguments to match one of these entries.
allowlist_enforced: true
allowlist:
  - name: "filesystem"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/home/me/work"]
    # Optional: hash the resolved command binary. If lockfile is set, hash
    # that file instead (for example a package-lock.json).
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"

servers:
  demo:
    # true trusts this server's initialize instructions, definition
    # descriptions/titles and completion values; they no longer latch
    # TAINT_SERVER_INSTRUCTIONS, TAINT_SERVER_METADATA or
    # TAINT_SERVER_COMPLETION. Default false.
    trust_metadata: false
    tools:
      read_ticket:
        class: read
      write_file:
        class: write
        # Additional argument keys that name a path. Content, URL and
        # destination keys cannot be used here.
        path_keys: [path, filename]
        # Directory roots where a tainted write needs no prompt.
        # Only valid for class: write.
        allow_paths:
          - "/home/me/work"
      http_post:
        class: egress
      run_command:
        class: exec
        # true means results from this tool do not latch taint. Default false.
        trust: false
```

`servers` may be omitted or empty for a policy that only sets global values.
The shorter `servers.<name>.<tool>` form is also accepted, with
`trust_metadata` alongside the tool entries. A tool that is not listed defaults
to `exec`, the most restrictive class that can still be approved by a human; it
is never treated as a read tool.

`trust_metadata` defaults to false. On first sight, non-empty initialize
instructions, definition descriptions/titles and completion values latch
`TAINT_SERVER_INSTRUCTIONS`, `TAINT_SERVER_METADATA` and
`TAINT_SERVER_COMPLETION`. Already-pinned unchanged definitions do not re-taint,
and pins marked `"reviewed": true` by `pins review` are accepted on restart. Set
`trust_metadata` to true only for a server whose metadata you have reviewed and
trust. In team mode the local policy can narrow a remote `true` to `false`, but
it cannot turn on metadata trust that the team floor did not grant.

## Built-in profiles

A profile supplies default classes for a known server's tool list. It is
selected automatically from the server command and package/image tokens (for
example `npx -y @modelcontextprotocol/server-filesystem` or
`uvx mcp-server-fetch`). If the command does not identify a profile, the
`--name` label is used as a fallback. `profile: auto` (the default) uses this
selection; `profile: none` disables it; `profile: <name>` forces one. An unknown
profile name is a startup error. `playwright` and `puppeteer` are aliases for
`browser`, `postgresql` for `postgres`, and `atlassian` for `jira`.

Short generic identifiers such as `git`, `shell`, `fetch` and `jira` match only
an exact command/package token or a path basename. Other identifiers must also
sit on a `-`, `_`, `/`, `@` or `.` boundary. Scoped packages found below
`node_modules` are matched as `@scope/pkg`, and a trailing `@version` is removed
without truncating a scoped package path.

A policy entry for a tool replaces the profile's class for that tool, even when
the entry only adds `path_keys` or `allow_paths`. To make a profile tool
unknown/restrictive again, set `class: exec`.

| Profile | Source used for the tool list | Typical identifiers |
|---|---|---|
| `filesystem` | npm `@modelcontextprotocol/server-filesystem` 2.2.0 | `@modelcontextprotocol/server-filesystem`, `mcp-server-filesystem`, `mcp/filesystem` |
| `git` | PyPI `mcp-server-git` 2026.11.4 | `mcp-server-git`, `mcp_server_git`, `mcp/git` |
| `github` | `github/github-mcp-server` v2.1.0, plus archived npm `@modelcontextprotocol/server-github` 2025.4.8 aliases | `github-mcp-server`, `github/github-mcp-server`, `@modelcontextprotocol/server-github` |
| `fetch` | PyPI `mcp-server-fetch` 2026.11.4 | `mcp-server-fetch`, `mcp_server_fetch`, `mcp/fetch` |
| `shell` | npm `mcp-shell` 0.1.3, `@mkusaka/mcp-shell-server` 0.1.1, `@mako10k/mcp-shell-server` 2.8.1 | `mcp-shell`, `mcp-shell-server`, `@mkusaka/mcp-shell-server` |
| `slack` | npm `@modelcontextprotocol/server-slack` 2025.4.25 | `@modelcontextprotocol/server-slack`, `mcp-server-slack`, `mcp/slack` |
| `postgres` | npm `@modelcontextprotocol/server-postgres` 0.6.2 | `@modelcontextprotocol/server-postgres`, `mcp-server-postgres`, `mcp/postgres` |
| `postgres-mcp` | `postgres-mcp` 0.3.0 (CrystalDBA) | `postgres-mcp`, `crystaldba/postgres-mcp`, `mcp/postgres-mcp` |
| `browser` | npm `@playwright/mcp` 0.0.84 and `@modelcontextprotocol/server-puppeteer` 2025.5.12 | `@playwright/mcp`, `playwright-mcp`, `mcp-server-puppeteer` |
| `notion` | npm `@notionhq/notion-mcp-server` 2.6.1 (Notion API 2025-09-03) | `@notionhq/notion-mcp-server`, `notion-mcp-server`, `mcp/notion` |
| `jira` | PyPI `mcp-atlassian` 0.23.1 | `mcp-atlassian`, `mcp_atlassian`, `jira-mcp-atlassian` |

The legacy `postgres` profile treats `query` as write because that server does
not enforce a read-only transaction. The `postgres-mcp` profile keeps `query`
read for CrystalDBA's restricted mode; `execute_sql` is write in both. Jira's
attachment downloads and Playwright's screenshot/snapshot tools are write
because they create files, while `browser_console_messages` and
`browser_network_requests` remain read.

Profiles are conservative defaults, not a trust decision you can skip: review
the class of any write, exec or egress tool before relying on it, and override
it in the policy file when your server exposes a different tool list. The
profile sources are also recorded in comments in
`cmd/sylenix-guard/main.go`.

`fetch` has only the egress-class `fetch` tool. If normal fetching should
continue after taint, list the hosts it may reach in `egress.allow_hosts`;
otherwise every tainted fetch is `EGRESS_TARGET`. The profile test uses an
allowlisted host for its read-side call and an unlisted host for the blocked
call.

## Server command allowlist

The allowlist stops a malicious client configuration from launching an arbitrary
command as an "MCP server". Each entry matches the configured command exactly
and the arguments as a list. An argument may use `*` or `?` as a wildcard;
otherwise it must match exactly. `args` is required: use `args: []` for a
command with no arguments.

`sha256` is optional. When present, the guard hashes the resolved command
binary before launch and refuses on a mismatch. If `lockfile` is also present,
the guard hashes that file instead, which lets you pin a package lock rather
than the package-runner binary. A missing or unreadable hash target is refused.
Without `sha256`, an entry matches by command path/name only; a bare command
name such as `python` trusts whatever `PATH` resolves to at launch.

If `allowlist_enforced` is omitted, a non-empty `allowlist` enforces it and an
empty one does not. `allowlist_enforced: true` with an empty list denies every
server. New installs and `sylenix-guard allow` set enforcement to true.

The allowlist is a launch control for a stdio child command. `sylenix-guard
proxy` has no child command and does not apply it to `--upstream`; use a
`servers.<name>` policy entry for the remote server's tool classes instead.

`allow` and `install` rewrite the policy file in a canonical form. Known fields
are preserved, but comments and original formatting are not.

A refused launch exits 2 before the child process is created, writes
`SERVER_NOT_ALLOWED` to the audit log, and explains how to approve the command.
The audit event records the command path and reason, never the argument values.

```bash
# Read a server from the supported MCP client configs, show it, confirm,
# and add its exact command/args to the policy allowlist.
sylenix-guard allow filesystem
sylenix-guard allow filesystem --policy ./policy.yaml --yes

# New installs write <state-dir>/policy.yaml with enforcement enabled and the
# servers present at install time, after confirmation. A custom --policy or
# --state-dir is also pinned in the wrapper written to each client config, so
# the installed server loads the same policy.
sylenix-guard install --yes
sylenix-guard install --policy ./policy.yaml --state-dir ./.state --yes
```

## Classes

| Class | Clean session | Tainted session |
|---|---|---|
| `read` | Forwarded | Forwarded. Results still latch taint unless `trust: true` or `--trust`. |
| `write` | Forwarded | Hard blocks first, then `allow_paths`, a live grant, the approval dialog, or default deny (`TAINT_SINK`). |
| `exec` | Forwarded | No `allow_paths` shortcut. A live grant or the approval dialog can allow it; otherwise `TAINT_SINK`. |
| `egress` | Forwarded | Every destination must match `egress.allow_hosts` and none may match `egress.deny_hosts`; then the call is allowed. Otherwise `EGRESS_TARGET`. |
| unlisted | Forwarded | Treated as `exec`. |

`allow_paths` entries are directory roots resolved with the same symlink and
`..` handling as `--allow-write-under`. Relative roots are interpreted against
the guard's working directory.

For non-`read` tools, hard blocks come before the class decision: a tainted
call whose path touches a sensitive name is `SENSITIVE_TARGET`, and a protected
agent-instruction or persistence target is `SENSITIVE_TARGET` (dialog-only when
`approval: dialog`). A `read` tool bypasses the sink checks, exactly like
`--readonly`; list only pure reads there.

For a non-`egress` tool that carries an egress argument, an allow-listed host
lifts the `EGRESS_TARGET` hard block but does not authorize the call by itself:
it still needs a human decision (`approval: dialog`), and with `approval: deny`
it is `TAINT_SINK`. Grants and `allow_paths` never cover egress.

## Sensitive paths

`sensitive_paths` adds glob patterns to the built-in floor. Patterns without a
slash match any path component; patterns with a slash match the path or any
suffix of it. Matching is case-insensitive, and `*`, `?` and `[...]` use Go's
`path.Match` syntax.

The built-in floor includes `.git`, `.env*`, `id_rsa*`, `id_ed25519*`,
`*.pem`, `*.key`, `*.p12`, `*.pfx` and the common project/config names
(`go.mod`, `package.json`, `Makefile`, `Dockerfile`, ...). A policy file can
add to that floor but cannot remove it. `.git` is hard-blocked, including
`.git/hooks`; no dialog, grant or scratch rule can approve it.

## Egress hosts

`allow_hosts` and `deny_hosts` are host names, not URLs. A leading `*.` matches
subdomains (`*.example.com` matches `a.example.com`). An optional `:port` is
ignored; matching uses the host. Deny wins over allow.
The host is taken from URL/URI values, destination-named arguments and
`host:port` values. A destination with no extractable host is not allow-listed.
Matching is textual on the argument value: the guard does not resolve DNS,
follow redirects or pin the resolved address.

## Flag precedence and deprecation

Flags that are explicitly set replace the corresponding policy section:

| Flag | Policy equivalent |
|---|---|
| `--readonly a,b` | `servers.<name>.tools.<tool>.class: read` (replaces all policy read classes) |
| `--trust a,b` | `servers.<name>.tools.<tool>.trust: true` (replaces all policy trust entries) |
| `--approve deny\|dialog` | `approval` |
| `--allow-write-under DIR` | `servers.<name>.tools.<tool>.allow_paths` (replaces all policy allow paths) |
| `--no-spotlight` | `spotlight: false` |

The guard prints a deprecation note to stderr for each of these flags when it
is set. `--grant`, `--reset-pins`, `--name`, `--state-dir`, `--policy-pubkey`
and `--policy-key` remain flag-only; signing keys are deliberately not stored
inside the policy file.

## Commands

```bash
# Check a file without starting a server. Exit 0 is valid; exit 2 is invalid.
sylenix-guard policy validate ./policy.yaml

# Print the built-in defaults as a valid policy file.
sylenix-guard policy print-default > policy.yaml

# Sign, verify, and inspect pin stores.
sylenix-guard keys init [--out DIR | --key PATH] [--force] [--state-dir DIR]
sylenix-guard policy sign --policy ./policy.yaml --key ~/.sylenix-keys/policy-signing.key
sylenix-guard policy verify --policy ./policy.yaml --pubkey ~/.sylenix-keys/policy-signing.key.pub
sylenix-guard pins sign --name filesystem --state-dir ~/.sylenix-poc --key ~/.sylenix-keys/policy-signing.key
sylenix-guard pins verify --name filesystem --state-dir ~/.sylenix-poc --pubkey ~/.sylenix-keys/policy-signing.key.pub

# Add the currently configured command for a named server.
sylenix-guard allow <name> [--policy PATH] [--state-dir DIR] [--yes]

# Install wraps MCP client configs and pre-populates the allowlist.
sylenix-guard install [--policy PATH] [--state-dir DIR] [--yes] [--dry-run]
```

## Checking prompt cost

`scripts/replay_profile_session.py` replays a recorded normal session through
the guard, with the profile selected from the fixture's package name. It counts
the calls that would need a human decision and reports prompts per active hour.
The default fixture is a 60-minute filesystem session; it must stay below ten
prompts per hour.

```bash
python scripts/replay_profile_session.py
python scripts/replay_profile_session.py --json
```

## Examples

### 1. Minimal demo server

```yaml
version: 1
approval: deny
servers:
  demo:
    tools:
      read_ticket:
        class: read
      write_file:
        class: write
      http_post:
        class: egress
```

Unknown tools such as a new `delete_ticket` are treated as `exec` after taint.
A clean session is forwarded as before.

### 2. Workspace filesystem with a scratch write root

```yaml
version: 1
approval: dialog
sensitive_paths:
  - "secrets/*"
  - "*.kdbx"
servers:
  filesystem:
    tools:
      read_file:
        class: read
      list_directory:
        class: read
      write_file:
        class: write
        path_keys: [path]
        allow_paths:
          - "/home/me/project"
      edit_file:
        class: write
        path_keys: [path]
        allow_paths:
          - "/home/me/project"
      delete_file:
        class: exec
```

Writes inside `/home/me/project` need no prompt after taint. A write outside it
asks the human. `delete_file` is `exec`, so even a path inside the project does
not get the scratch shortcut.

### 3. Network tools with an egress allowlist

```yaml
version: 1
approval: deny
egress:
  allow_hosts:
    - "api.example.com"
    - "*.internal.example.com"
  deny_hosts:
    - "169.254.169.254"
    - "metadata.example.com"
servers:
  net-tools:
    tools:
      fetch_page:
        class: egress
      http_post:
        class: egress
      run_shell:
        class: exec
```

After taint, `http_post` may reach `api.example.com` or a subdomain of
`internal.example.com`; anything else, including the metadata address, is
`EGRESS_TARGET`. `run_shell` needs a grant or a dialog and never uses an
`allow_paths` shortcut.
