# SPDX-License-Identifier: Apache-2.0

"""Regression probes for human-approved taint clearing.

The guard owns the decision: clear-taint writes a request into the state dir,
the running guard shows an OS dialog, and only a human "Clear Taint" click
clears the in-memory latch. These tests use a fake dialog on PATH so no real
dialog appears. They also prove that MCP tool calls, host methods, server
messages and environment variables cannot clear taint.

Run after building the guard:

    python3 tests/probes/test_clear_taint.py
"""
import hashlib
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GUARD = os.environ.get("SYLENIX_GUARD") or os.path.join(
    ROOT, "bin", "sylenix-guard.exe" if sys.platform == "win32" else "sylenix-guard")
FAKE = os.path.join(ROOT, "demo", "fake_server.py")
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
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def write_json(path, obj):
    write(path, json.dumps(obj, indent=2) + "\n")


def run(args, env, cwd, input_text=None, timeout=30):
    return subprocess.run([GUARD, *args], env=env, cwd=cwd, input=input_text,
                          capture_output=True, text=True, timeout=timeout)


def install_fake_dialog(base):
    """Put a fake OS dialog first on PATH. It only answers the dialog calls."""
    bin_dir = os.path.join(base, "fakebin")
    os.makedirs(bin_dir, exist_ok=True)
    env = dict(os.environ)
    if sys.platform == "win32":
        source = os.path.join(base, "fake_dialog.go")
        write(source, '''package main

import (
    "os"
    "strings"
)

func main() {
    msg := strings.ToLower(os.Getenv("SYLENIX_MSG"))
    if strings.Contains(msg, "clear the taint") {
        switch os.Getenv("FAKE_DIALOG") {
        case "allow":
            os.Exit(0)
        case "error":
            os.Exit(2)
        default:
            os.Exit(1)
        }
    }
    if log := os.Getenv("FAKE_DIALOG_LOG"); log != "" {
        f, err := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
        if err == nil {
            _, _ = f.WriteString("sink\\n")
            _ = f.Close()
        }
    }
    os.Exit(1)
}
''')
        exe = os.path.join(bin_dir, "powershell.exe")
        subprocess.run(["go", "build", "-o", exe, source], cwd=ROOT, check=True,
                       capture_output=True, text=True)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    elif sys.platform == "darwin":
        script = os.path.join(bin_dir, "osascript")
        write(script, '''#!/bin/sh
case "$*" in
  *"clear the taint"*)
    if [ "$FAKE_DIALOG" = "allow" ]; then
      echo "button returned:Clear Taint"
    else
      echo "button returned:Deny"
    fi
    exit 0 ;;
  *)
    if [ -n "$FAKE_DIALOG_LOG" ]; then echo sink >> "$FAKE_DIALOG_LOG"; fi
    echo "button returned:Deny"
    exit 0 ;;
esac
''')
        os.chmod(script, 0o755)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    else:
        script = os.path.join(bin_dir, "zenity")
        write(script, '''#!/bin/sh
case "$*" in
  *"clear the taint"*)
    if [ "$FAKE_DIALOG" = "allow" ]; then
      echo "Clear Taint"
      exit 0
    elif [ "$FAKE_DIALOG" = "error" ]; then
      exit 2
    else
      echo "Deny"
      exit 0
    fi ;;
  *)
    if [ -n "$FAKE_DIALOG_LOG" ]; then echo sink >> "$FAKE_DIALOG_LOG"; fi
    exit 1 ;;
esac
''')
        os.chmod(script, 0o755)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    return env


class Session:
    def __init__(self, state, env, name="t", flags=(), server_args=None):
        if server_args is None:
            server_args = [sys.executable, FAKE]
        cmd = [GUARD, "--name", name, "--state-dir", state, *flags, "--", *server_args]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=env)
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
                                 "clientInfo": {"name": "clear-taint", "version": "0"}})
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


def clear_taint(env, cwd, name, state, timeout=30):
    return run(["clear-taint", "--name", name, "--state-dir", state], env, cwd, timeout=timeout)


def audit_rows(state, name):
    path = os.path.join(state, "audit-" + name + ".jsonl")
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def events(rows, name):
    return [row for row in rows if row.get("event") == name]


def case_clear_allow(fake_env):
    print("human approves clearing taint")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        env = dict(fake_env)
        env["FAKE_DIALOG"] = "allow"
        s = Session(state, env, flags=("--approve", "deny"))
        s.start()
        s.call("read_ticket")
        blocked = s.call("write_file", {"path": "x", "content": "x"})
        check("clear allow: tainted sink is blocked", rule(blocked) == "TAINT_SINK", str(blocked))

        p = clear_taint(env, base, "t", state)
        check("clear allow: CLI exits 0", p.returncode == 0, p.stderr)
        check("clear allow: CLI reports cleared", "cleared" in p.stdout.lower(), p.stdout)

        allowed = s.call("write_file", {"path": "x", "content": "x"})
        check("clear allow: sink is allowed after clear", "result" in allowed, str(allowed))
        check("clear allow: guard exits cleanly", s.close() == 0)

        rows = audit_rows(state, "t")
        clears = events(rows, "CLEAR_TAINT")
        check("clear allow: audit has CLEAR_TAINT", len(clears) == 1, str(clears))
        check("clear allow: CLEAR_TAINT has who", bool(clears and clears[0].get("who")), str(clears))
        check("clear allow: CLEAR_TAINT has ts", bool(clears and clears[0].get("ts")), str(clears))
        check("clear allow: CLEAR_TAINT has request id", bool(clears and clears[0].get("request_id")), str(clears))
        check("clear allow: CLEAR_TAINT granted", bool(clears) and clears[0].get("granted") is True, str(clears))
        text = open(os.path.join(state, "audit-t.jsonl"), encoding="utf-8").read()
        check("clear allow: audit never contains the nonce", "nonce" not in text.lower(), text[-400:])
        listing = os.listdir(state)
        check("clear allow: control files cleaned up",
              not any(n.startswith("control-") or n.startswith("clear-taint-") for n in listing),
              str(listing))


def case_clear_deny(fake_env):
    print("human denies clearing taint")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        env = dict(fake_env)
        env["FAKE_DIALOG"] = "deny"
        s = Session(state, env, flags=("--approve", "deny"))
        s.start()
        s.call("read_ticket")
        p = clear_taint(env, base, "t", state)
        check("clear deny: CLI exits 1", p.returncode == 1, p.stderr)
        check("clear deny: CLI reports denied", "denied" in p.stdout.lower(), p.stdout)
        blocked = s.call("write_file", {"path": "x", "content": "x"})
        check("clear deny: sink stays blocked", rule(blocked) == "TAINT_SINK", str(blocked))
        check("clear deny: guard exits cleanly", s.close() == 0)

        rows = audit_rows(state, "t")
        denials = events(rows, "CLEAR_TAINT_DENIED")
        check("clear deny: audit has CLEAR_TAINT_DENIED", len(denials) == 1, str(denials))
        check("clear deny: denied event has who", bool(denials and denials[0].get("who")), str(denials))
        check("clear deny: denied event has ts", bool(denials and denials[0].get("ts")), str(denials))
        check("clear deny: denied event not granted", bool(denials) and denials[0].get("granted") is False, str(denials))
        check("clear deny: no CLEAR_TAINT", not events(rows, "CLEAR_TAINT"), str(rows))


def case_not_tainted(fake_env):
    print("clear-taint on a clean session does not open a dialog")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        log = os.path.join(base, "dialogs.log")
        env = dict(fake_env)
        env["FAKE_DIALOG"] = "allow"
        env["FAKE_DIALOG_LOG"] = log
        s = Session(state, env, flags=("--approve", "deny"))
        s.start()
        p = clear_taint(env, base, "t", state)
        check("clear clean: CLI exits 0", p.returncode == 0, p.stderr)
        check("clear clean: CLI says not tainted", "not tainted" in p.stdout.lower(), p.stdout)
        check("clear clean: no dialog was opened", not os.path.exists(log) or os.path.getsize(log) == 0)
        check("clear clean: guard exits cleanly", s.close() == 0)
        rows = audit_rows(state, "t")
        check("clear clean: audit has CLEAR_TAINT_NOT_NEEDED", len(events(rows, "CLEAR_TAINT_NOT_NEEDED")) == 1, str(rows))
        check("clear clean: no CLEAR_TAINT", not events(rows, "CLEAR_TAINT"), str(rows))


def case_mcp_tool(fake_env):
    print("an MCP tool call named clear-taint cannot clear taint")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        env = dict(fake_env)
        env["FAKE_DIALOG"] = "deny"
        s = Session(state, env, flags=("--approve", "deny"))
        s.start()
        s.call("read_ticket")
        resp = s.call("clear-taint", {"action": "clear"})
        check("mcp tool: clear-taint call is blocked", rule(resp) == "TAINT_SINK", str(resp))
        blocked = s.call("write_file", {"path": "x", "content": "x"})
        check("mcp tool: taint is still latched", rule(blocked) == "TAINT_SINK", str(blocked))
        check("mcp tool: guard exits cleanly", s.close() == 0)
        check("mcp tool: no CLEAR_TAINT", not events(audit_rows(state, "t"), "CLEAR_TAINT"))


def case_host_method(fake_env):
    print("a host JSON-RPC method named clear-taint cannot clear taint")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        env = dict(fake_env)
        env["FAKE_DIALOG"] = "deny"
        s = Session(state, env, flags=("--approve", "deny"))
        s.start()
        s.call("read_ticket")
        s.send("sylenix/clear-taint", {"action": "clear"})
        resp = s.recv()
        check("host method: method is forwarded, not acted on", "error" in resp, str(resp))
        blocked = s.call("write_file", {"path": "x", "content": "x"})
        check("host method: taint is still latched", rule(blocked) == "TAINT_SINK", str(blocked))
        check("host method: guard exits cleanly", s.close() == 0)
        check("host method: no CLEAR_TAINT", not events(audit_rows(state, "t"), "CLEAR_TAINT"))


def case_server_message(fake_env):
    print("server clear-taint requests and notifications cannot clear taint")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        env = dict(fake_env)
        env["FAKE_DIALOG"] = "deny"
        env["FAKE_CLEAR_TAINT_NOTIFY"] = "1"
        s = Session(state, env, flags=("--approve", "deny"))
        s.start()
        s.call("read_ticket")
        s.send("ping")
        seen = set()
        deadline = time.time() + 10
        while time.time() < deadline and seen != {"request", "notification"}:
            try:
                msg = s.recv(timeout=max(0.1, deadline - time.time()))
            except Exception:
                break
            if msg.get("method") == "sylenix/clear-taint":
                seen.add("request" if "id" in msg else "notification")
        check("server message: request was forwarded", "request" in seen, str(seen))
        check("server message: notification was forwarded", "notification" in seen, str(seen))
        blocked = s.call("write_file", {"path": "x", "content": "x"})
        check("server message: taint is still latched", rule(blocked) == "TAINT_SINK", str(blocked))
        check("server message: guard exits cleanly", s.close() == 0)
        rows = audit_rows(state, "t")
        check("server message: server request is audited", len(events(rows, "server_request")) >= 1, str(rows))
        check("server message: no CLEAR_TAINT", not events(rows, "CLEAR_TAINT"), str(rows))


def case_env_var(fake_env):
    print("an environment variable cannot clear taint")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        dialog_log = os.path.join(base, "dialogs.log")
        env = dict(fake_env)
        env["SYLENIX_CLEAR_TAINT"] = "1"
        env["FAKE_DIALOG"] = "allow"
        env["FAKE_DIALOG_LOG"] = dialog_log
        s = Session(state, env, flags=("--approve", "deny"))
        s.start()
        s.call("read_ticket")
        blocked = s.call("write_file", {"path": "x", "content": "x"})
        check("env var: taint is still latched", rule(blocked) == "TAINT_SINK", str(blocked))
        check("env var: no dialog was opened", not os.path.exists(dialog_log) or os.path.getsize(dialog_log) == 0)
        check("env var: guard exits cleanly", s.close() == 0)
        rows = audit_rows(state, "t")
        check("env var: no CLEAR_TAINT", not events(rows, "CLEAR_TAINT"), str(rows))
        check("env var: no CLEAR_TAINT_DENIED", not events(rows, "CLEAR_TAINT_DENIED"), str(rows))


def case_dialog_failure(fake_env):
    print("a failed dialog fails closed")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        env = dict(fake_env)
        env["FAKE_DIALOG"] = "error"
        s = Session(state, env, flags=("--approve", "deny"))
        s.start()
        s.call("read_ticket")
        p = clear_taint(env, base, "t", state)
        check("dialog failure: CLI exits 1", p.returncode == 1, p.stderr)
        blocked = s.call("write_file", {"path": "x", "content": "x"})
        check("dialog failure: taint stays latched", rule(blocked) == "TAINT_SINK", str(blocked))
        check("dialog failure: guard exits cleanly", s.close() == 0)
        check("dialog failure: no CLEAR_TAINT", not events(audit_rows(state, "t"), "CLEAR_TAINT"))


def case_read_only_profile(fake_env):
    print("read-only profile tools never prompt in dialog mode")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        dialog_log = os.path.join(base, "dialogs.log")
        call_log = os.path.join(base, "calls.log")
        env = dict(fake_env)
        env["FAKE_DIALOG"] = "deny"
        env["FAKE_DIALOG_LOG"] = dialog_log
        env["PROFILE_TOOLS"] = "read_file,write_file"
        env["PROFILE_CALL_LOG"] = call_log
        s = Session(state, env, flags=("--approve", "dialog"),
                    server_args=[sys.executable, PROFILE_SERVER,
                                 "@modelcontextprotocol/server-filesystem"])
        s.start()
        first = s.call("read_file", {"path": "README.md"})
        check("profile read: first read taints and is allowed", "result" in first, str(first))
        second = s.call("read_file", {"path": "README.md"})
        check("profile read: second read is allowed without a dialog", "result" in second, str(second))
        check("profile read: no dialog opened for reads",
              not os.path.exists(dialog_log) or os.path.getsize(dialog_log) == 0)
        blocked = s.call("write_file", {"path": "x", "content": "x"})
        check("profile write: write still prompts and is denied", rule(blocked) == "APPROVAL_DENIED", str(blocked))
        check("profile write: dialog was opened for the write",
              os.path.exists(dialog_log) and os.path.getsize(dialog_log) > 0)
        check("profile write: write never reached the server",
              os.path.exists(call_log) and "write_file" not in open(call_log, encoding="utf-8").read())
        check("profile read: guard exits cleanly", s.close() == 0)
        rows = audit_rows(state, "t")
        read_approvals = [r for r in events(rows, "approval") if r.get("tool") == "read_file"]
        write_approvals = [r for r in events(rows, "approval") if r.get("tool") == "write_file"]
        check("profile read: no approval event for reads", not read_approvals, str(read_approvals))
        check("profile write: one approval event for the write", len(write_approvals) == 1, str(write_approvals))


def case_usage(fake_env):
    print("clear-taint usage and stale control files")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        env = dict(fake_env)
        p = run(["clear-taint"], env, base)
        check("usage: missing --name exits 2", p.returncode == 2, p.stderr)
        p = run(["clear-taint", "--name", "missing", "--state-dir", state], env, base)
        check("usage: no running session exits 2", p.returncode == 2, p.stderr)
        p = run(["clear-taint", "--name", "\u200b", "--state-dir", state], env, base)
        check("usage: control characters in --name exit 2", p.returncode == 2, p.stderr)

        name = "stale"
        digest = hashlib.sha256(name.encode()).hexdigest()[:32]
        old = "2026-01-01T00:00:00Z"
        write_json(os.path.join(state, f"control-{digest}.json"), {
            "version": 1, "name": name, "pid": 1, "nonce": "a" * 64,
            "started_at": old, "heartbeat": old,
        })
        p = run(["clear-taint", "--name", name, "--state-dir", state], env, base)
        check("usage: stale control file exits 2", p.returncode == 2, p.stderr)
        check("usage: stale control file is explained", "stale" in (p.stdout + p.stderr).lower(), p.stdout + p.stderr)


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    with tempfile.TemporaryDirectory(prefix="sylenix-fake-dialog-") as fake_base:
        fake_env = install_fake_dialog(fake_base)
        case_clear_allow(fake_env)
        case_clear_deny(fake_env)
        case_not_tainted(fake_env)
        case_mcp_tool(fake_env)
        case_host_method(fake_env)
        case_server_message(fake_env)
        case_env_var(fake_env)
        case_dialog_failure(fake_env)
        case_read_only_profile(fake_env)
        case_usage(fake_env)
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
