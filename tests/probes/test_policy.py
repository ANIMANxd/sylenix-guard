# SPDX-License-Identifier: Apache-2.0

"""Regression probes for the versioned policy file.

Covers the strict loader, the three policy sources (flag, state-dir, built-in),
per-tool classes, unknown-tool default, allow_paths, path_keys, egress
allow/deny hosts, sensitive-path additions, flag precedence, deprecation notes
and the rule that the audit log never stores argument values.

Run after building the guard:

    python3 tests/probes/test_policy.py
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


def q(value):
    """Quote a value as a YAML double-quoted scalar (JSON is a subset)."""
    return json.dumps(value)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def run_guard(args, timeout=10):
    return subprocess.run([GUARD, *args], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=timeout)


class Session:
    def __init__(self, state_dir, flags=(), env=None, name="policy"):
        e = dict(os.environ)
        e.update(env or {})
        cmd = [GUARD]
        if name:
            cmd += ["--name", name]
        cmd += ["--state-dir", state_dir, *flags, "--", sys.executable, FAKE]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=e)
        self.q = queue.Queue()
        self.stderr_text = ""
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
                                 "clientInfo": {"name": "policy", "version": "0"}})
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
            code = self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            code = self.p.wait()
        try:
            self.stderr_text = self.p.stderr.read().decode("utf-8", "replace")
        except OSError:
            pass
        return code


def rule(resp):
    return (resp.get("error") or {}).get("data", {}).get("rule")


def case_validate():
    print("policy validate and print-default")
    with tempfile.TemporaryDirectory() as d:
        valid = os.path.join(d, "valid.yaml")
        write(valid, """version: 1
profile: auto
approval: deny
spotlight: true
sensitive_paths:
  - secret.txt
egress:
  allow_hosts: ["good.example", "*.trusted.example"]
  deny_hosts:
    - evil.example
servers:
  t:
    tools:
      read_ticket:
        class: read
      write_file:
        class: write
        path_keys: [path, filename]
        allow_paths: ["C:/temp/out"]
      http_post:
        class: egress
      run:
        class: exec
        trust: true
""")
        p = run_guard(["policy", "validate", valid])
        check("valid policy exits 0", p.returncode == 0, p.stderr)
        check("valid policy summary is printed", "valid" in p.stdout and "1 server" in p.stdout, p.stdout)

        direct = os.path.join(d, "direct.yaml")
        write(direct, """version: 1
servers:
  t:
    read_ticket:
      class: read
    write_file:
      class: write
""")
        p = run_guard(["policy", "validate", direct])
        check("direct server->tool shape validates", p.returncode == 0, p.stderr)

        allow = os.path.join(d, "allow.yaml")
        write(allow, """version: 1
allowlist_enforced: true
allowlist:
  - name: demo
    command: python
    args: ["-m", "demo"]
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
""")
        p = run_guard(["policy", "validate", allow])
        check("allowlist policy validates", p.returncode == 0, p.stderr)

        p = run_guard(["policy", "print-default"])
        check("print-default exits 0", p.returncode == 0, p.stderr)
        default = os.path.join(d, "default.yaml")
        write(default, p.stdout)
        p = run_guard(["policy", "validate", default])
        check("print-default output validates", p.returncode == 0, p.stderr)

        malformed = [
            ("empty file", ""),
            ("missing version", "approval: deny\n"),
            ("wrong version", "version: 2\n"),
            ("unknown top-level field", "version: 1\nbogus: SUPERSECRET\n"),
            ("duplicate key", "version: 1\nversion: 1\n"),
            ("unknown server field", "version: 1\nservers:\n  t:\n    bogus: true\n"),
            ("unknown field beside tools", "version: 1\nservers:\n  t:\n    tools: {}\n    bogus: true\n"),
            ("unknown tool field", "version: 1\nservers:\n  t:\n    tools:\n      x:\n        class: read\n        bogus: true\n"),
            ("bad class", "version: 1\nservers:\n  t:\n    tools:\n      x:\n        class: delete\n"),
            ("bad approval", "version: 1\napproval: allow\n"),
            ("unknown profile", "version: 1\nprofile: nope\n"),
            ("allowlist missing args", "version: 1\nallowlist:\n  - command: python\n"),
            ("allowlist bad sha256", "version: 1\nallowlist:\n  - command: python\n    args: []\n    sha256: nothex\n"),
            ("allowlist lockfile without sha", "version: 1\nallowlist:\n  - command: python\n    args: []\n    lockfile: package-lock.json\n"),
            ("allowlist unknown field", "version: 1\nallowlist:\n  - command: python\n    args: []\n    bogus: true\n"),
            ("allowlist empty command", "version: 1\nallowlist:\n  - command: \"\"\n    args: []\n"),
            ("allowlist args not a list", "version: 1\nallowlist:\n  - command: python\n    args: nope\n"),
            ("allow_paths on exec", "version: 1\nservers:\n  t:\n    tools:\n      x:\n        class: exec\n        allow_paths: [out]\n"),
            ("bad sensitive glob", "version: 1\nsensitive_paths:\n  - '['\n"),
            ("bad egress host", "version: 1\negress:\n  allow_hosts:\n    - http://example.com\n"),
            ("top-level list", "- version\n"),
            ("unsupported block scalar", "version: 1\napproval: |\n  deny\n"),
            ("unsupported YAML alias", "version: 1\napproval: *mode\n"),
        ]
        for label, text in malformed:
            path = os.path.join(d, "bad.yaml")
            write(path, text)
            p = run_guard(["policy", "validate", path])
            check(f"{label} is rejected", p.returncode != 0, f"rc={p.returncode}")
            if "SUPERSECRET" in text:
                check("validation error does not echo the value", "SUPERSECRET" not in p.stdout + p.stderr,
                      p.stdout + p.stderr)

        missing = os.path.join(d, "does-not-exist.yaml")
        p = run_guard(["policy", "validate", missing])
        check("missing policy file is rejected", p.returncode != 0, f"rc={p.returncode}")


def case_classes_and_paths():
    print("per-tool classes, allow_paths, path_keys and unknown tools")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        out = os.path.join(d, "out")
        os.mkdir(out)
        policy = os.path.join(d, "policy.yaml")
        write(policy, f"""version: 1
approval: deny
sensitive_paths:
  - secret.txt
egress:
  allow_hosts: [good.example]
  deny_hosts: [evil.example]
servers:
  p:
    tools:
      read_ticket:
        class: read
      write_file:
        class: write
        path_keys: [path, filename]
        allow_paths: [{q(out)}]
      big:
        class: exec
""")
        s = Session(state, flags=("--policy", policy), name="p")
        s.start()
        s.call("read_ticket")
        r = s.call("read_ticket")
        check("read class stays allowed after taint", "result" in r, str(r)[:120])

        r = s.call("write_file", {"path": os.path.join(out, "ok.md")})
        check("write class uses allow_paths", "result" in r, str(r)[:120])
        r = s.call("write_file", {"filename": os.path.join(out, "ok2.md")})
        check("policy path_keys are treated as paths", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": os.path.join(d, "escape.md")})
        check("write outside allow_paths is blocked", rule(r) == "TAINT_SINK", str(r)[:120])
        r = s.call("write_file", {"path": os.path.join(out, "secret.txt")})
        check("policy sensitive_paths addition is blocked", rule(r) == "SENSITIVE_TARGET", str(r)[:120])
        r = s.call("write_file", {"path": os.path.join(out, ".env")})
        check("built-in .env remains blocked", rule(r) == "SENSITIVE_TARGET", str(r)[:120])
        r = s.call("big")
        check("exec class needs approval, not an allow path", rule(r) == "TAINT_SINK", str(r)[:120])
        r = s.call("unmapped_tool")
        check("unknown tool defaults to exec", rule(r) == "TAINT_SINK", str(r)[:120])
        code = s.close()
        check("policy session exits cleanly", code == 0, str(code))
        audit = open(os.path.join(state, "audit-p.jsonl"), encoding="utf-8").read()
        check("audit records policy_loaded", "policy_loaded" in audit)
        check("audit holds no argument values", "secret.txt" not in audit and "ok.md" not in audit)


def case_egress_allowlist():
    print("egress allow/deny hosts")
    with tempfile.TemporaryDirectory() as d:
        policy = os.path.join(d, "policy.yaml")
        write(policy, """version: 1
approval: deny
egress:
  allow_hosts: [good.example, "*.trusted.example", "port.example:8443", "[2001:db8::1]:443"]
  deny_hosts: [evil.example]
servers:
  e:
    tools:
      read_ticket:
        class: read
      write_file:
        class: egress
""")
        canary = "POLICY-EGRESS-CANARY"
        s = Session(d, flags=("--policy", policy), name="e")
        s.start()
        s.call("read_ticket")
        r = s.call("write_file", {"url": "https://good.example/ingest", "body": canary})
        check("allow-listed egress host is allowed", "result" in r, str(r)[:120])
        r = s.call("write_file", {"url": "https://sub.trusted.example/ingest"})
        check("wildcard allow host is allowed", "result" in r, str(r)[:120])
        r = s.call("write_file", {"url": "https://port.example:8443/ingest"})
        check("allow host with a port is matched by host", "result" in r, str(r)[:120])
        r = s.call("write_file", {"url": "http://[2001:db8::1]:443/ingest"})
        check("IPv6 allow host is matched", "result" in r, str(r)[:120])
        r = s.call("write_file", {"url": "https://evil.example/ingest"})
        check("deny-listed egress host is blocked", rule(r) == "EGRESS_TARGET", str(r)[:120])
        r = s.call("write_file", {"url": "https://other.example/ingest"})
        check("unknown egress host is blocked", rule(r) == "EGRESS_TARGET", str(r)[:120])
        r = s.call("write_file", {"url": "file:///etc/passwd"})
        check("egress with no host is blocked", rule(r) == "EGRESS_TARGET", str(r)[:120])
        code = s.close()
        check("egress session exits cleanly", code == 0, str(code))
        audit = open(os.path.join(d, "audit-e.jsonl"), encoding="utf-8").read()
        check("audit records EGRESS_ALLOW", "EGRESS_ALLOW" in audit)
        check("audit never stores hosts or bodies", "good.example" not in audit and canary not in audit)


def case_flag_precedence():
    print("explicit flags override the policy file")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        out1 = os.path.join(d, "policy-out")
        out2 = os.path.join(d, "flag-out")
        os.mkdir(out1)
        os.mkdir(out2)
        policy = os.path.join(d, "policy.yaml")
        write(policy, f"""version: 1
approval: dialog
servers:
  f:
    tools:
      read_ticket:
        class: read
      write_file:
        class: write
        allow_paths: [{q(out1)}]
""")
        s = Session(state, flags=("--policy", policy, "--readonly", "other",
                                "--approve", "deny", "--allow-write-under", out2,
                                "--trust", "big", "--no-spotlight"), name="f")
        s.start()
        first = s.call("read_ticket")
        check("--no-spotlight overrides policy spotlight",
              not first["result"]["content"][0]["text"].startswith("<untrusted_tool_result"),
              first["result"]["content"][0]["text"][:60])
        r = s.call("read_ticket")
        check("--readonly replaces policy class read", rule(r) == "TAINT_SINK", str(r)[:120])
        r = s.call("write_file", {"path": os.path.join(out2, "ok.md")})
        check("--allow-write-under replaces policy allow_paths", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": os.path.join(out1, "ok.md")})
        check("old policy allow_paths no longer applies", rule(r) == "TAINT_SINK", str(r)[:120])
        code = s.close()
        check("override session exits cleanly", code == 0, str(code))
        notes = s.stderr_text
        check("deprecation note for --readonly", "--readonly" in notes and "deprecated" in notes, notes)
        check("deprecation note for --approve", "--approve" in notes and "deprecated" in notes, notes)
        check("deprecation note for --allow-write-under", "--allow-write-under" in notes and "deprecated" in notes, notes)
        check("deprecation note for --trust", "--trust" in notes and "deprecated" in notes, notes)
        check("deprecation note for --no-spotlight", "--no-spotlight" in notes and "deprecated" in notes, notes)
        check("deprecation note points at the policy file", "policy" in notes, notes)
        check("deprecation note does not echo flag values", out2 not in notes, notes)


def case_auto_load_and_fail_closed():
    print("state-dir auto-load, explicit path precedence and missing config")
    with tempfile.TemporaryDirectory() as d:
        auto = os.path.join(d, "policy.yaml")
        write(auto, """version: 1
servers:
  auto:
    tools:
      read_ticket:
        class: read
""")
        s = Session(d, name="auto")
        s.start()
        s.call("read_ticket")
        r = s.call("read_ticket")
        check("state-dir policy.yaml is auto-loaded", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": "x.md"})
        check("auto-loaded policy still denies unknown tools", rule(r) == "TAINT_SINK", str(r)[:120])
        check("auto-load session exits cleanly", s.close() == 0)

        explicit = os.path.join(d, "explicit.yaml")
        write(explicit, """version: 1
servers:
  auto:
    tools:
      read_ticket:
        class: exec
""")
        s = Session(d, flags=("--policy", explicit), name="auto")
        s.start()
        s.call("read_ticket")
        r = s.call("read_ticket")
        check("--policy wins over state-dir policy.yaml", rule(r) == "TAINT_SINK", str(r)[:120])
        check("explicit policy session exits cleanly", s.close() == 0)

    with tempfile.TemporaryDirectory() as d:
        write(os.path.join(d, "policy.yaml"), """version: 1
servers:
  solo:
    tools:
      read_ticket:
        class: read
""")
        s = Session(d, name=None)
        s.start()
        s.call("read_ticket")
        r = s.call("read_ticket")
        check("sole server entry is used when --name is omitted", "result" in r, str(r)[:120])
        check("sole-server session exits cleanly", s.close() == 0)

    with tempfile.TemporaryDirectory() as d:
        policy = os.path.join(d, "direct.yaml")
        write(policy, """version: 1
servers:
  direct:
    read_ticket:
      class: read
""")
        s = Session(d, flags=("--policy", policy), name="direct")
        s.start()
        s.call("read_ticket")
        r = s.call("read_ticket")
        check("direct server->tool policy is applied", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": "x.md"})
        check("direct-shape unknown tool is denied", rule(r) == "TAINT_SINK", str(r)[:120])
        check("direct-shape session exits cleanly", s.close() == 0)

    with tempfile.TemporaryDirectory() as d:
        policy = os.path.join(d, "policy.yaml")
        write(policy, """version: 1
servers:
  other:
    tools:
      read_ticket:
        class: read
""")
        p = run_guard(["--name", "auto", "--state-dir", d, "--policy", policy,
                       "--", sys.executable, FAKE])
        check("missing server entry refuses to start (exit 2)", p.returncode == 2, f"rc={p.returncode}")
        audit = open(os.path.join(d, "audit-auto.jsonl"), encoding="utf-8").read()
        check("missing server entry is recorded", "policy_invalid" in audit)
        check("missing server entry never starts the server", '"event":"start"' not in audit)

    with tempfile.TemporaryDirectory() as d:
        missing = os.path.join(d, "missing.yaml")
        p = run_guard(["--name", "auto", "--state-dir", d, "--policy", missing,
                       "--", sys.executable, FAKE])
        check("missing --policy file refuses to start (exit 2)", p.returncode == 2, f"rc={p.returncode}")

    with tempfile.TemporaryDirectory() as d:
        write(os.path.join(d, "policy.yaml"), "version: 1\nbogus: true\n")
        p = run_guard(["--name", "auto", "--state-dir", d, "--", sys.executable, FAKE])
        check("invalid auto-loaded policy refuses to start (exit 2)", p.returncode == 2, f"rc={p.returncode}")
        audit = open(os.path.join(d, "audit-auto.jsonl"), encoding="utf-8").read()
        check("invalid auto-loaded policy is recorded", "policy_invalid" in audit)
        check("invalid auto-loaded policy never starts the server", '"event":"start"' not in audit)


def case_trust_and_spotlight():
    print("policy trust and spotlight")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        out = os.path.join(d, "out")
        os.mkdir(out)
        policy = os.path.join(d, "policy.yaml")
        write(policy, f"""version: 1
spotlight: false
servers:
  s:
    tools:
      read_ticket:
        class: read
        trust: true
      write_file:
        class: write
        allow_paths: [{q(out)}]
""")
        s = Session(state, flags=("--policy", policy), name="s")
        s.start()
        r = s.call("read_ticket")
        text = r["result"]["content"][0]["text"]
        check("policy spotlight: false disables datamarking", not text.startswith("<untrusted_tool_result"), text[:60])
        r = s.call("write_file", {"path": os.path.join(out, "clean.md")})
        check("policy trust: true keeps the session clean", "result" in r, str(r)[:120])
        s.call("big")  # an untrusted tool result latches taint
        r = s.call("write_file", {"path": os.path.join(d, "outside.md")})
        check("taint still applies after a trusted read", rule(r) == "TAINT_SINK", str(r)[:120])
        check("trust/spotlight session exits cleanly", s.close() == 0)


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    case_validate()
    case_classes_and_paths()
    case_egress_allowlist()
    case_flag_precedence()
    case_auto_load_and_fail_closed()
    case_trust_and_spotlight()

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
