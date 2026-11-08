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
