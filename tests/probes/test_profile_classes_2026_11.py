# SPDX-License-Identifier: Apache-2.0

"""Regression probes for F8 profile classes and F9 package-path matching."""

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GUARD = os.environ.get("SYLENIX_GUARD") or os.path.join(
    ROOT, "bin", "sylenix-guard.exe" if sys.platform == "win32" else "sylenix-guard")
PROFILE_SERVER = os.path.join(ROOT, "tests", "probes", "profile_server.py")

passed, failed = 0, []


def check(label, cond, detail=""):
    global passed
    if cond:
        passed += 1
        print(f"  ok   {label}")
    else:
        failed.append(label)
        print(f"  FAIL {label} {detail}")


class Session:
    def __init__(self, state_dir, name, tools, identifier, env=None, server=None):
        e = dict(os.environ)
        e["PROFILE_TOOLS"] = tools
        e.update(env or {})
        if server is None:
            server = [sys.executable, PROFILE_SERVER, identifier]
        cmd = [GUARD, "--name", name, "--state-dir", state_dir, "--", *server]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=e)
        self.q = queue.Queue()
        self._id = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            self.q.put(line)
        self.q.put(None)

    def send(self, method, params=None):
        self._id += 1
        message = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            message["params"] = params
        self.p.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
        self.p.stdin.flush()
        return self._id

    def notify(self, method):
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method},
                                      separators=(",", ":")).encode() + b"\n")
        self.p.stdin.flush()

    def recv(self, timeout=15):
        line = self.q.get(timeout=timeout)
        if line is None:
            raise RuntimeError("guard closed stdout")
        return json.loads(line.decode("utf-8"))

    def start(self):
        self.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "profile-probe", "version": "0"}})
        self.recv()
        self.notify("notifications/initialized")
        self.send("tools/list")
        return self.recv()

    def call(self, name, args=None):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv()

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            return self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return self.p.wait(timeout=5)


def rule(resp):
    return ((resp.get("error") or {}).get("data") or {}).get("rule")


def audit_events(state, name):
    path = os.path.join(state, "audit-" + name + ".jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def selected_profile(identifier, name):
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        s = Session(state, name, "", identifier)
        try:
            s.start()
        finally:
            s.close()
        loaded = [event for event in audit_events(state, name)
                  if event.get("event") == "policy_loaded"]
        return loaded[-1].get("profile", "") if loaded else ""


def profile_calls(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def case_classes(label, identifier, tools, read_tool, read_args, blocked, read_only=()):
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        log = os.path.join(d, "calls.log")
        s = Session(state, "pc-" + label, tools, identifier,
                    env={"PROFILE_CALL_LOG": log})
        responses = {}
        try:
            s.start()
            taint = s.call(read_tool, read_args)
            responses[read_tool] = taint
            for tool in read_only:
                responses[tool] = s.call(tool, {})
            for tool in blocked:
                args = {"sql": "select 1"} if tool == "query" else {}
                responses[tool] = s.call(tool, args)
        finally:
            s.close()
        problems = []
        if "result" not in responses[read_tool]:
            problems.append("%s read %s was blocked" % (label, read_tool))
        for tool in read_only:
            if "result" not in responses[tool]:
                problems.append("%s read %s was blocked" % (label, tool))
        for tool in blocked:
            if rule(responses[tool]) != "TAINT_SINK":
                problems.append("%s %s was allowed (rule=%r)"
                                % (label, tool, rule(responses[tool])))
        calls = profile_calls(log)
        leaked = [tool for tool in blocked if tool in calls]
        if leaked:
            problems.append("%s blocked tool(s) reached the server: %s"
                            % (label, ", ".join(leaked)))
        check(f"{label}: shell, screenshot and database write classes hold",
              not problems, "; ".join(problems))


def test_f8_classes():
    print("F8 write classifications")
    case_classes(
        "jira", "mcp-atlassian",
        "get_issue,download_attachments,jira_download_attachments",
        "get_issue", {"issue_key": "PROJ-1"},
        ["download_attachments", "jira_download_attachments"],
    )
    case_classes(
        "browser", "@playwright/mcp",
        "browser_console_messages,browser_network_requests,"
        "browser_take_screenshot,browser_snapshot,browser_pdf_save",
        "browser_console_messages", {},
        ["browser_take_screenshot", "browser_snapshot", "browser_pdf_save"],
        read_only=["browser_network_requests"],
    )
    case_classes(
        "postgres-legacy", "@modelcontextprotocol/server-postgres",
        "list_schemas,query,execute_sql",
        "list_schemas", {},
        ["query", "execute_sql"],
    )
    case_classes(
        "postgres-mcp", "postgres-mcp",
        "query,execute_sql",
        "query", {"sql": "select 1"},
        ["execute_sql"],
        read_only=["query"],
    )


def test_f8_matching():
    print("F8 identifier matching")
    false_positive_cases = (
        ("digital-ocean-mcp", "digital-ocean-mcp"),
        ("git-helper-mcp", "git-helper-mcp"),
        ("digital-shell-thing", "digital-shell-thing"),
        ("my-fetch-service", "my-fetch-service"),
        ("not-jira-ish", "not-jira-ish"),
    )
    for name, identifier in false_positive_cases:
        got = selected_profile(identifier, "pm-" + name)
        check(f"{identifier} does not select a short generic profile",
              got == "", f"profile={got!r}")

    positives = (
        ("vendor-mcp-server-git-wrapper", "git"),
        ("/opt/bin/git", "git"),
        ("@modelcontextprotocol/server-filesystem@2.2.0", "filesystem"),
        ("/x/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
         "filesystem"),
    )
    for identifier, want in positives:
        got = selected_profile(identifier, "pp-" + want + str(abs(hash(identifier)))[:6])
        check(f"{identifier} selects {want}", got == want, f"profile={got!r}")


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    test_f8_classes()
    test_f8_matching()
    print(f"\n{passed} passed, {len(failed)} failed")
    if failed:
        print("failed: " + ", ".join(failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
