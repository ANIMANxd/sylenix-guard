# Policy file

Sylenix Guard can read one versioned policy file per run. It replaces the
repetitive `--readonly`, `--trust`, `--approve`, `--allow-write-under` and
`--no-spotlight` flags; the flags still work and override the file when set.

## Where the file comes from

1. `--policy PATH`, if the flag is set.
2. `<state-dir>/policy.yaml`, if that file exists.
3. The built-in defaults.

An explicit or auto-loaded file that cannot be read or parsed is a startup
error (exit 2); the guard does not fall back to a weaker policy. If no file is
present, the built-in defaults apply. `--name` selects the server entry. When
`servers` is non-empty and `--name` is not set, a file with exactly one server
entry uses that entry; otherwise the requested name must exist in `servers`.

The file is read once at startup and is not watched or signed. Treat it as
trusted local configuration.

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

servers:
  demo:
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
The shorter `servers.<name>.<tool>` form is also accepted. A tool that is not
listed defaults to `exec`, the most restrictive class that can still be approved
by a human; it is never treated as a read tool.

## Built-in profiles

A profile supplies default classes for a known server's tool list. It is
selected automatically from the server command and package/image tokens (for
example `npx -y @modelcontextprotocol/server-filesystem` or
`uvx mcp-server-fetch`). If the command does not identify a profile, the
`--name` label is used as a fallback. `profile: auto` (the default) uses this
selection; `profile: none` disables it; `profile: <name>` forces one. An unknown
profile name is a startup error. `playwright` and `puppeteer` are aliases for
`browser`, `postgresql` for `postgres`, and `atlassian` for `jira`.

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
| `postgres` | npm `@modelcontextprotocol/server-postgres` 0.6.2 and `postgres-mcp` 0.3.0 | `@modelcontextprotocol/server-postgres`, `mcp-server-postgres`, `postgres-mcp` |
| `browser` | npm `@playwright/mcp` 0.0.84 and `@modelcontextprotocol/server-puppeteer` 2025.5.12 | `@playwright/mcp`, `playwright-mcp`, `mcp-server-puppeteer` |
| `notion` | npm `@notionhq/notion-mcp-server` 2.6.1 (Notion API 2025-09-03) | `@notionhq/notion-mcp-server`, `notion-mcp-server`, `mcp/notion` |
| `jira` | PyPI `mcp-atlassian` 0.23.1 | `mcp-atlassian`, `mcp_atlassian`, `jira-mcp-atlassian` |

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
add to that floor but cannot remove it. `.git/hooks` keeps its protected-target
treatment and can still be approved through the dialog.

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
is set. `--grant`, `--reset-pins`, `--name` and `--state-dir` remain flag-only.

## Commands

```bash
# Check a file without starting a server. Exit 0 is valid; exit 2 is invalid.
sylenix-guard policy validate ./policy.yaml

# Print the built-in defaults as a valid policy file.
sylenix-guard policy print-default > policy.yaml
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
