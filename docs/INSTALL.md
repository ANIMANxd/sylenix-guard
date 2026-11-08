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
