"""Built-in policy profile probes.

For each shipped profile: select it automatically from the server command /
package token, taint the session with a read call, prove the same read call is
still allowed, then prove a write or egress call is blocked. Also checks a
per-tool policy override, `profile: none`, and an explicit `profile:` choice.

Run after building the guard:

    python3 tests/probes/test_profiles.py
"""
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


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


class Session:
    def __init__(self, state_dir, identifier, flags=(), env=None, name="t", tools=()):
        e = dict(os.environ)
        e.update(env or {})
        e["PROFILE_TOOLS"] = ",".join(tools)
        args = [sys.executable, PROFILE_SERVER]
        if identifier:
            args.append(identifier)
        cmd = [GUARD, "--name", name, "--state-dir", state_dir, *flags, "--", *args]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=e)
        self.q = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self._id = 0

    def _read(self):
        for line in self.p.stdout:
            self.q.put(line)
        self.q.put(None)

    def raw(self, text):
        self.p.stdin.write(text.encode() + b"\n")
        self.p.stdin.flush()

    def send(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.raw(json.dumps(msg))
        return self._id

    def recv(self, timeout=10):
        line = self.q.get(timeout=timeout)
        if line is None:
            raise RuntimeError("guard closed stdout")
        return json.loads(line)

    def start(self):
        self.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "profile", "version": "0"}})
        self.recv()
        self.raw(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.send("tools/list")
        self.recv()

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
            return None


def rule(resp):
    return (resp.get("error") or {}).get("data", {}).get("rule")


# profile, package token, read tool, read args, blocked tool, blocked args, rule
PROFILES = [
    ("filesystem", "@modelcontextprotocol/server-filesystem",
     "read_file", {"path": "README.md"},
     "write_file", {"path": "notes.md", "content": "x"}, "TAINT_SINK"),
    ("git", "mcp-server-git",
     "git_status", {"repo_path": "."},
     "git_commit", {"repo_path": ".", "message": "x"}, "TAINT_SINK"),
    ("github", "github-mcp-server",
     "get_file_contents", {"owner": "o", "repo": "r", "path": "README.md"},
     "create_or_update_file", {"owner": "o", "repo": "r", "path": "README.md",
                               "content": "x", "message": "x"}, "TAINT_SINK"),
    ("fetch", "mcp-server-fetch",
     "fetch", {"url": "https://good.example/page"},
     "fetch", {"url": "https://evil.example/page"}, "EGRESS_TARGET"),
    ("shell", "mcp-shell",
     "read_execution_output", {"output_id": "1"},
     "run_command", {"command": "echo hi"}, "TAINT_SINK"),
    ("slack", "@modelcontextprotocol/server-slack",
     "slack_list_channels", {},
     "slack_post_message", {"channel_id": "C1", "text": "hi"}, "TAINT_SINK"),
    ("postgres", "@modelcontextprotocol/server-postgres",
     "query", {"sql": "select 1"},
     "execute_sql", {"sql": "delete from t"}, "TAINT_SINK"),
    ("browser", "@playwright/mcp",
     "browser_snapshot", {},
     "browser_navigate", {"url": "https://evil.example"}, "EGRESS_TARGET"),
    ("notion", "@notionhq/notion-mcp-server",
     "post-search", {"query": "roadmap"},
     "post-page", {"parent": {"page_id": "x"}, "properties": {}}, "TAINT_SINK"),
    ("jira", "mcp-atlassian",
     "get_issue", {"issue_key": "PROJ-1"},
     "create_issue", {"project_key": "PROJ", "summary": "x"}, "TAINT_SINK"),
]


def case_profile(profile, identifier, read_tool, read_args, blocked_tool, blocked_args, want_rule):
    print(f"profile {profile}")
    with tempfile.TemporaryDirectory() as d:
        flags = ()
        if profile == "fetch":
            policy = os.path.join(d, "policy.yaml")
            write(policy, """version: 1
approval: deny
egress:
  allow_hosts: [good.example]
""")
            flags = ("--policy", policy)
        log = os.path.join(d, "calls.log")
        s = Session(d, identifier, flags=flags, env={"PROFILE_CALL_LOG": log},
                    tools=(read_tool, blocked_tool))
        s.start()
        # The first read is allowed on a clean session and taints it.
        first = s.call(read_tool, read_args)
        check(f"{profile}: tainting read succeeds", "result" in first, str(first)[:120])
        second = s.call(read_tool, read_args)
        check(f"{profile}: read stays allowed after taint", "result" in second, str(second)[:120])
        blocked = s.call(blocked_tool, blocked_args)
        check(f"{profile}: {blocked_tool} is blocked after taint",
              "result" not in blocked and rule(blocked) == want_rule, f"rule={rule(blocked)}")
        code = s.close()
        check(f"{profile}: clean exit", code == 0, str(code))
        calls = open(log, encoding="utf-8").read().split() if os.path.exists(log) else []
        if blocked_tool == read_tool:
            check(f"{profile}: blocked call never reached the server", len(calls) == 2, str(calls))
        else:
            check(f"{profile}: blocked call never reached the server", blocked_tool not in calls, str(calls))


def case_policy_override():
    print("policy override and explicit profile selection")
    with tempfile.TemporaryDirectory() as d:
        policy = os.path.join(d, "policy.yaml")
        write(policy, """version: 1
approval: deny
servers:
  t:
    tools:
      read_file:
        class: exec
""")
        s = Session(d, "@modelcontextprotocol/server-filesystem", flags=("--policy", policy),
                    tools=("read_file", "list_directory"))
        s.start()
        s.call("list_directory", {"path": "."})
        r = s.call("read_file", {"path": "README.md"})
        check("policy class overrides the profile class", rule(r) == "TAINT_SINK", str(r)[:120])
        check("override session exits cleanly", s.close() == 0)

    with tempfile.TemporaryDirectory() as d:
        policy = os.path.join(d, "policy.yaml")
        write(policy, """version: 1
approval: deny
servers:
  t:
    tools:
      write_file:
        class: read
""")
        s = Session(d, "@modelcontextprotocol/server-filesystem", flags=("--policy", policy),
                    tools=("read_file", "write_file"))
        s.start()
        s.call("read_file", {"path": "README.md"})
        r = s.call("write_file", {"path": "notes.md", "content": "x"})
        check("policy read class overrides a profile write class", "result" in r, str(r)[:120])
        check("read override session exits cleanly", s.close() == 0)

    with tempfile.TemporaryDirectory() as d:
        policy = os.path.join(d, "policy.yaml")
        write(policy, """version: 1
approval: deny
profile: none
""")
        s = Session(d, "@modelcontextprotocol/server-filesystem", flags=("--policy", policy),
                    tools=("read_file", "list_directory"))
        s.start()
        s.call("list_directory", {"path": "."})
        r = s.call("read_file", {"path": "README.md"})
        check("profile: none disables auto-selection", rule(r) == "TAINT_SINK", str(r)[:120])
        check("profile none session exits cleanly", s.close() == 0)

    with tempfile.TemporaryDirectory() as d:
        policy = os.path.join(d, "policy.yaml")
        write(policy, """version: 1
approval: deny
profile: filesystem
""")
        # The command carries no filesystem identifier: the explicit profile
        # selection must be what applies.
        s = Session(d, "", flags=("--policy", policy), tools=("read_file", "write_file"))
        s.start()
        s.call("read_file", {"path": "README.md"})
        r = s.call("read_file", {"path": "README.md"})
        check("explicit profile: read stays allowed", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": "notes.md", "content": "x"})
        check("explicit profile: write is blocked", rule(r) == "TAINT_SINK", str(r)[:120])
        check("explicit profile session exits cleanly", s.close() == 0)

    with tempfile.TemporaryDirectory() as d:
        # No package token and no policy: --name is the fallback selector.
        s = Session(d, "", name="filesystem", tools=("read_file", "write_file"))
        s.start()
        s.call("read_file", {"path": "README.md"})
        r = s.call("read_file", {"path": "README.md"})
        check("--name fallback selects a profile", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": "notes.md", "content": "x"})
        check("--name fallback profile still blocks writes", rule(r) == "TAINT_SINK", str(r)[:120])
        check("name fallback session exits cleanly", s.close() == 0)


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    for entry in PROFILES:
        case_profile(*entry)
    case_policy_override()
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
