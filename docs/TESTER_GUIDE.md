# Sylenix Guard: tester guide

Thanks for trying this early version. It is a proof of concept, so expect rough edges.

## What it is

Sylenix Guard is a small program that sits between your AI app (Claude Desktop or Cursor) and one MCP server. Once the AI has read content from a tool, Guard stops it from running anything that changes things, such as writing files or sending requests, unless you say so in a pop-up. The idea is that a malicious instruction hidden in a document or ticket cannot make your AI act on its own.

The pop-up has three buttons: **Deny** (block this call), **Allow Once** (let this one call through), and **Allow Tool for 15m** (let this tool keep working for fifteen minutes, limited to the folder it just used). The third button is there so normal work does not turn into a stream of pop-ups.

## What it does not do

- It only watches the one MCP server you wrap with it. Your app's built-in tools, and anything you paste in yourself, are not covered.
- It is not a complete security product. It reduces one kind of risk.
- You will see approval pop-ups. Clicking Allow Tool for 15m when you are doing real work in one folder keeps them down to roughly one per work session. How many is one of the things we are measuring.
- Two things are always blocked, with no pop-up: calls that send data to a network address (URLs), and calls that touch `.git`, `.env`, key files or config files like `package.json` and `Makefile`. If you genuinely need one of those while the guard is on, tell us; that is a deliberate choice we want to hear about.

## Requirements

macOS or Windows, Claude Desktop or Cursor (or anything else that speaks MCP over stdio), and an MCP server you already use. Linux works too if you have `zenity` installed for the pop-ups.

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

4. In `--readonly`, list the tools that only read and never change anything or reach the network. If you are unsure about a tool, leave it off the list; tools that are not listed are treated as risky. If the server writes into one working folder, add `"--allow-write-under", "/FULL/PATH/TO/THAT/FOLDER"` to the args: writes into that folder then pass without a pop-up.
5. Quit and restart the app.
6. Ask the AI to do something that reads a file, then something that changes one. You should see a pop-up on the second step.

## Turning it off

Put your original server command back in the config and restart the app.

## What it records

A log on your own computer at `~/.sylenix-poc/audit-<name>.jsonl`: tool names, the names of arguments (not their values), and what Guard decided. Stdio mode makes no network connections and sends nothing anywhere. Proxy mode connects only to the `--upstream` URL you configure; it forwards auth headers but never logs or stores them.

## What we need back

After a week, run the summary script we gave you (`summarize_audit.py --name <name>`), send us the output, and answer the questions in `FEEDBACK_LOG.md`. Tell us about anything that broke or annoyed you, even if it was small.
