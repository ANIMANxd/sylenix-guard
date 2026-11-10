# SPDX-License-Identifier: Apache-2.0

"""A generic MCP-shaped server used by the built-in profile tests.

It advertises the tool names in PROFILE_TOOLS (comma-separated) and answers
every tools/call with a short text result. It exists so a profile can be
exercised without running the real filesystem, Git, GitHub, Slack, Postgres,
browser, Notion or Jira server.

Set PROFILE_CALL_LOG to append one tool name per call that reaches the server.
"""
import json
import os
import sys

TOOLS = [name.strip() for name in os.environ.get("PROFILE_TOOLS", "").split(",") if name.strip()]
CALL_LOG = os.environ.get("PROFILE_CALL_LOG")


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def result(req_id, text="ok"):
    send({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}})


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    method, rid = req.get("method"), req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "profile-fake", "version": "0"},
        }})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": name, "description": name, "inputSchema": {"type": "object", "properties": {}}}
            for name in TOOLS
        ]}})
    elif method == "tools/call":
        name = (req.get("params") or {}).get("name", "")
        if CALL_LOG:
            with open(CALL_LOG, "a", encoding="utf-8") as fh:
                fh.write(name + "\n")
        result(rid, "ok")
    elif rid is not None:
        send({"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32601, "message": "Method not found",
        }})
