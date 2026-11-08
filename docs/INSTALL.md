# Installing Guard in MCP clients

`sylenix-guard install` rewrites existing local stdio MCP server entries so the
client starts Guard, and Guard starts the original server:

```bash
sylenix-guard install --yes        # apply
sylenix-guard install --dry-run    # show the diff, write nothing
sylenix-guard uninstall --yes      # restore the original entries
```

Without `--yes`, the command prints a diff and asks before writing. Every write
is preceded by a timestamped backup next to the config:

```text
<config>.sylenix-backup-<UTC timestamp>
```

Only existing config files are edited; Guard does not create a config file.
Remote/HTTP/SSE/WebSocket entries, entries already using Guard, malformed
entries and unparseable configs are skipped and reported. A broken config is
left untouched.

## Exact config paths

`~` is the user's home directory. On Linux, `$XDG_CONFIG_HOME` defaults to
`~/.config`. Project paths are relative to the directory where `install` or
`uninstall` is run.

| Client | macOS | Windows | Linux | Server map |
|---|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` | `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json` (normally `~/.config/Claude/...`) | `mcpServers` |
| Claude Code (user) | `~/.claude.json` | `%USERPROFILE%\.claude.json` | `~/.claude.json` | `mcpServers` |
| Claude Code (project) | `./.mcp.json` | `./.mcp.json` | `./.mcp.json` | `mcpServers` |
| Cursor (user) | `~/.cursor/mcp.json` | `%USERPROFILE%\.cursor\mcp.json` | `~/.cursor/mcp.json` | `mcpServers` |
| Cursor (project) | `./.cursor/mcp.json` | `./.cursor/mcp.json` | `./.cursor/mcp.json` | `mcpServers` |
| VS Code settings | `~/Library/Application Support/Code/User/settings.json` | `%APPDATA%\Code\User\settings.json` | `$XDG_CONFIG_HOME/Code/User/settings.json` | `mcp.servers` |
| VS Code user MCP | `~/Library/Application Support/Code/User/mcp.json` | `%APPDATA%\Code\User\mcp.json` | `$XDG_CONFIG_HOME/Code/User/mcp.json` | `servers` |
| VS Code workspace | `./.vscode/mcp.json` | `./.vscode/mcp.json` | `./.vscode/mcp.json` | `servers` |

VS Code settings and VS Code MCP files also accept a root `mcpServers` map for
compatibility. The VS Code settings file is a normal `settings.json`; only its
`mcp.servers` object is changed and unrelated settings are preserved.

## What the wrapped entry looks like

A stdio entry such as:

```json
{
  "command": "npx",
  "args": ["-y", "@example/server"],
  "env": {"EXAMPLE_TOKEN": "value"}
}
```

becomes:

```json
{
  "command": "/absolute/path/to/sylenix-guard",
  "args": ["--", "npx", "-y", "@example/server"],
  "env": {"EXAMPLE_TOKEN": "value"},
  "_sylenixGuard": {
    "version": 1,
    "hadArgs": true,
    "hadEnv": true
  }
}
```

The original command, argument order and environment values are kept. The
`_sylenixGuard` metadata only records whether `args` and `env` were originally
present, so `uninstall` can restore omissions exactly. `uninstall` reconstructs
the original entry from the wrapped entry itself; it does not depend on the
backup being present.

Restart the client after installing or uninstalling so it reloads the config.

## Release artifacts and verification

Releases are built by GitHub Actions with GoReleaser only for tags matching
`vX.Y.Z`. The workflow runs `make check` and the protocol self-test before the
release job starts.

The release contains:

- `sylenix-guard_<version>_<os>_<arch>.tar.gz` (macOS/Linux)
- `sylenix-guard_<version>_windows_amd64.zip`
- `checksums.txt`
- `checksums.txt.sigstore.json` (Cosign keyless signature bundle)
- `*.sbom.json` (Syft SBOMs)
- the generated Homebrew formula and Scoop manifest

Download the artifacts, checksums, and signature bundle into one directory.

### Verify checksums

Linux:

```bash
sha256sum --check --ignore-missing checksums.txt
```

macOS:

```bash
shasum -a 256 --check --ignore-missing checksums.txt
```

### Verify the Cosign keyless signature

Replace the owner, repository, and tag with the release you are verifying. The
identity must match the workflow that produced the release, and the issuer must
be GitHub Actions:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/ANIMANxd/sylenix-guard/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

Only after that succeeds, verify the downloaded archives with the checksum
command above.

### SBOM

The `*.sbom.json` files are CycloneDX/SPDX documents from Syft. Inspect one with:

```bash
jq '.components | length' sylenix-guard_<version>_linux_amd64.tar.gz.sbom.json
```

### Homebrew

GoReleaser marks its formula generator as deprecated in favour of casks; this
project keeps the formula because a formula is the requested Homebrew artifact.

When a `HOMEBREW_TAP_TOKEN` is configured for the repository, GoReleaser
publishes the formula to `ANIMANxd/homebrew-tap`:

```bash
brew tap ANIMANxd/tap
brew install ANIMANxd/tap/sylenix-guard
```

Without that token (for example on a fork test tag), the formula is still
generated as `dist/homebrew/Formula/sylenix-guard.rb` and attached to the
GitHub release. Install it directly from a local checkout or download:

```bash
brew install --formula ./dist/homebrew/Formula/sylenix-guard.rb
```

### Scoop

When a `SCOOP_BUCKET_TOKEN` is configured, GoReleaser publishes the manifest to
`ANIMANxd/scoop-bucket`:

```powershell
scoop bucket add sylenix https://github.com/ANIMANxd/scoop-bucket
scoop install sylenix/sylenix-guard
```

Without the token, the generated manifest is in `dist/scoop/sylenix-guard.json`
and is attached to the GitHub release. Install it from the downloaded file:

```powershell
scoop install .\sylenix-guard.json
```

The `HOMEBREW_TAP_TOKEN` and `SCOOP_BUCKET_TOKEN` secrets need write access to
the respective tap/bucket repository. If they are absent, the release still
succeeds and the generated manifests remain available as local/release files.
