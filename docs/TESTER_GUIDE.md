# Sylenix Guard: tester guide

Thanks for trying this early version. It is a proof of concept, so expect rough edges.

## What it is

Sylenix Guard is a small program that sits between your AI app (Claude Desktop or Cursor) and one MCP server. Once the AI has read content from a tool, Guard stops it from running anything that changes things, such as writing files or sending requests, unless you click Allow in a pop-up. The idea is that a malicious instruction hidden in a document or ticket cannot make your AI act on its own.

## What it does not do

- It only watches the one MCP server you wrap with it. Your app's built-in tools, and anything you paste in yourself, are not covered.
- It is not a complete security product. It reduces one kind of risk.
- You will see approval pop-ups, possibly many. How many is one of the things we are measuring.

## Requirements

macOS, Claude Desktop or Cursor, and an MCP server you already use. Windows is not supported yet.

## Install

1. Copy `sylenix-guard` somewhere permanent and note its full path.
2. Open your app's MCP config. For Claude Desktop that is `~/Library/Application Support/Claude/claude_desktop_config.json`.
3. For the server you want to protect, wrap its command like this. Keep your original command and arguments after the `--`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/FULL/PATH/TO/sylenix-guard",
      "args": [
        "--name", "my-server",
        "--approve", "dialog",
        "--readonly", "tool_that_only_reads,another_read_only_tool",
        "--",
        "YOUR_ORIGINAL_COMMAND", "your", "original", "arguments"
      ]
    }
  }
}
```

4. In `--readonly`, list the tools that only read and never change anything or reach the network. If you are unsure about a tool, leave it off the list; tools that are not listed are treated as risky.
5. Quit and restart the app.
6. Ask the AI to do something that reads a file, then something that changes one. You should see a pop-up on the second step.

## Turning it off

Put your original server command back in the config and restart the app.

## What it records

A log on your own computer at `~/.sylenix-poc/audit-<name>.jsonl`: tool names, the names of arguments (not their values), and what Guard decided. Guard makes no network connections and sends nothing anywhere.

## What we need back

After a week, run the summary script we gave you (`summarize_audit.py --name <name>`), send us the output, and answer the questions in `FEEDBACK_LOG.md`. Tell us about anything that broke or annoyed you, even if it was small.
