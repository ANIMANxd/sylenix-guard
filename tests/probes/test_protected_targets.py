"""Regression probes for agent-instruction and persistence targets.

Every path is first written before taint (it must stay allowed), then the same
session is tainted and the write must be blocked by the protected-target class
even though the target sits inside --allow-write-under (and, in the second
mode, inside a scoped --grant).

Run after building the guard:

    python3 tests/probes/test_protected_targets.py
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
FAKE = os.path.join(ROOT, "demo", "fake_server.py")

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
    def __init__(self, state_dir, flags=(), env=None):
        e = dict(os.environ)
        e.update(env or {})
        cmd = [GUARD, "--name", "protect", "--state-dir", state_dir,
               "--readonly", "read_ticket", *flags, "--", sys.executable, FAKE]
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
                                 "clientInfo": {"name": "protect", "version": "0"}})
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


def categories(out):
    return [
        ("agent instructions", [
            "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
            ".cursor/rules/agent.mdc",
        ]),
        ("mcp and editor config", [
            ".mcp.json", "mcp.json", "claude_desktop_config.json",
            ".vscode/settings.json", ".vscode/tasks.json", ".idea/workspace.xml",
        ]),
        ("ci and hooks", [
            ".github/workflows/ci.yml", ".gitlab-ci.yml", ".git/hooks/pre-commit",
            ".husky/pre-commit",
        ]),
        ("shell startup", [
            ".bashrc", ".zshrc", ".profile", ".bash_profile",
            "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
            "Documents/WindowsPowerShell/profile.ps1",
        ]),
        ("cron", [
            "etc/cron.d/job", "etc/crontab", "var/spool/cron/crontabs/user",
            "usr/lib/cron/tabs/user", "cron/evil",
        ]),
        ("launchd", [
            "Library/LaunchAgents/evil.plist", "Library/LaunchDaemons/evil.plist",
            "launchd/evil.plist",
        ]),
        ("systemd user units", [
            ".config/systemd/user/evil.service", "systemd/evil.service",
        ]),
        ("windows startup", [
            "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.lnk",
            "Startup/evil.lnk",
        ]),
        ("agent config directories", [
            ".claude/settings.json", ".claude/settings.local.json",
            ".claude/commands/run.md", ".claude/agents/reviewer.md",
            ".claude/hooks/pre-tool.sh",
        ]),
        ("codex config", [
            ".codex/config.toml", ".codex/prompts/run.md",
        ]),
        ("gemini config", [
            ".gemini/settings.json", ".gemini/commands/run.toml",
        ]),
        ("continue config", [
            ".continue/config.json", ".continue/rules/run.md",
        ]),
        ("ssh config", [
            ".ssh/authorized_keys", ".ssh/config",
        ]),
        ("shell login files", [
            ".zshenv", ".zprofile", ".zlogin", ".bash_login",
        ]),
        ("fish config", [
            ".config/fish/config.fish", ".config/fish/functions/run.fish",
        ]),
        ("git config", [
            ".gitconfig", ".git/config",
        ]),
        ("desktop autostart", [
            ".config/autostart/evil.desktop",
        ]),
        ("package manager credentials", [
            ".npmrc", ".pypirc", ".netrc",
        ]),
        ("guard state and keys", [
            ".sylenix-poc/audit-protect.jsonl",
            ".sylenix-poc/pins-protect.json",
            ".sylenix-keys/policy-signing.key",
            ".sylenix-keys/README.txt",
        ]),
    ]


def run_mode(label, mode):
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        out = os.path.join(d, "out")
        os.mkdir(out)
        if mode == "scratch":
            flags = ("--allow-write-under", out)
        else:
            flags = ("--grant", "write_file:" + out + "=5m")
        # Keep write_file results from latching taint during the pre-taint
        # phase; the explicit read_ticket below is the only taint source.
        s = Session(state, flags=(*flags, "--trust", "write_file"))
        s.start()

        for category, rels in categories(out):
            for rel in rels:
                path = os.path.join(out, rel.replace("/", os.sep))
                r = s.call("write_file", {"path": path})
                check(f"{label}: {category}: allowed before taint", "result" in r, str(r)[:120])

        s.call("read_ticket")
        for category, rels in categories(out):
            for rel in rels:
                path = os.path.join(out, rel.replace("/", os.sep))
                r = s.call("write_file", {"path": path})
                check(f"{label}: {category}: blocked after taint",
                      "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")

        r = s.call("write_file", {"path": "$HOME/AGENTS.md"})
        check(f"{label}: env-expanded protected path is blocked",
              "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")
        check(f"{label}: clean exit", s.close() == 0)


def state_dir_test():
    """The configured --state-dir is protected even when it is inside a scratch root."""
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "out")
        os.mkdir(out)
        state = os.path.join(out, "guard-state")
        s = Session(state, flags=("--allow-write-under", out, "--trust", "write_file"))
        s.start()

        target = os.path.join(state, "guard-owned.json")
        r = s.call("write_file", {"path": target})
        check("state dir: configured --state-dir is allowed before taint",
              "result" in r, str(r)[:120])

        s.call("read_ticket")
        r = s.call("write_file", {"path": target})
        check("state dir: configured --state-dir is blocked after taint",
              "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")

        r = s.call("write_file", {"path": os.path.join("guard-state", "relative.json")})
        check("state dir: relative path under the scratch root is blocked",
              "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")

        r = s.call("write_file", {"path": os.path.join(state, "sub", "new.json")})
        check("state dir: a new file below the state dir is blocked",
              "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")

        r = s.call("write_file", {"path": os.path.join(out, "ok.md")})
        check("state dir: a sibling scratch write stays allowed", "result" in r, str(r)[:120])
        check("state dir: clean exit", s.close() == 0)


def dialog_approval_test():
    if not sys.platform.startswith("linux"):
        print("  skip dialog approval: fake zenity is Linux-only")
        return
    with tempfile.TemporaryDirectory() as d:
        bindir = os.path.join(d, "bin")
        os.mkdir(bindir)
        zenity = os.path.join(bindir, "zenity")
        with open(zenity, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("#!/bin/sh\necho 'Allow Tool for 15m'\nexit 0\n")
        os.chmod(zenity, 0o755)

        state = os.path.join(d, "state")
        out = os.path.join(d, "out")
        os.mkdir(out)
        env = {"PATH": bindir + os.pathsep + os.environ.get("PATH", "")}
        s = Session(state, flags=("--allow-write-under", out, "--approve", "dialog"), env=env)
        s.start()
        s.call("read_ticket")
        r = s.call("write_file", {"path": os.path.join(out, "AGENTS.md")})
        check("dialog: protected target can be approved", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": os.path.join(out, "CLAUDE.md")})
        check("dialog: a human 15m grant covers protected targets", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": os.path.join(out, ".git", "config")})
        check("dialog: .git/config remains hard blocked",
              "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")
        check("dialog: clean exit", s.close() == 0)


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    run_mode("scratch", "scratch")
    run_mode("grant", "grant")
    state_dir_test()
    dialog_approval_test()

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
