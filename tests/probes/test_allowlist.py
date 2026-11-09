"""Regression probes for the server-command allowlist.

Covers:
  - an unapproved server is refused before launch (SERVER_NOT_ALLOWED)
  - an approved exact command/args starts
  - a changed binary or lockfile SHA-256 is refused
  - `sylenix-guard allow <name>` reads the configured command, confirms and writes policy
  - `sylenix-guard install --yes` pre-populates the allowlist for servers present
  - install pins custom --policy/--state-dir paths in the wrapper it writes

Run after building the guard:

    python3 tests/probes/test_allowlist.py
"""
import hashlib
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


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def run(args, env, cwd, input_text=None, timeout=15):
    return subprocess.run([GUARD, *args], env=env, cwd=cwd, input=input_text,
                          capture_output=True, text=True, timeout=timeout)


class Session:
    def __init__(self, state_dir, policy, command, args, env=None, name="t"):
        e = dict(os.environ)
        e.update(env or {})
        cmd = [GUARD, "--name", name, "--state-dir", state_dir, "--policy", policy,
               "--", command, *args]
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
                                 "clientInfo": {"name": "allowlist", "version": "0"}})
        self.recv()
        self.raw(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.send("tools/list")
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


def case_unapproved_refused():
    print("unapproved server is refused before launch")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        policy = os.path.join(d, "policy.yaml")
        write(policy, """version: 1
allowlist_enforced: true
allowlist:
  - name: "other"
    command: "definitely-not-this-command"
    args: []
""")
        p = run(["--name", "t", "--state-dir", state, "--policy", policy,
                 "--", sys.executable, PROFILE_SERVER], dict(os.environ), d)
        check("unapproved server exits 2", p.returncode == 2, f"rc={p.returncode}")
        check("refusal names SERVER_NOT_ALLOWED", "SERVER_NOT_ALLOWED" in p.stderr, p.stderr[-300:])
        check("refusal explains how to approve", "sylenix-guard allow" in p.stderr, p.stderr[-300:])
        audit = open(os.path.join(state, "audit-t.jsonl"), encoding="utf-8").read()
        check("audit records SERVER_NOT_ALLOWED", "SERVER_NOT_ALLOWED" in audit)
        check("unapproved server never starts", '"event":"start"' not in audit)


def case_allow_and_start():
    print("allow command writes an exact entry and the approved server starts")
    with tempfile.TemporaryDirectory() as d:
        home = os.path.join(d, "home")
        project = os.path.join(d, "project")
        os.makedirs(home)
        os.makedirs(project)
        env = dict(os.environ)
        env.update({"HOME": home, "USERPROFILE": home,
                    "APPDATA": os.path.join(d, "appdata"),
                    "XDG_CONFIG_HOME": os.path.join(d, "xdg")})
        write(os.path.join(home, ".claude.json"), json.dumps({"mcpServers": {
            "approved": {"command": sys.executable, "args": [PROFILE_SERVER]},
        }}, indent=2) + "\n")
        policy = os.path.join(d, "policy.yaml")
        declined = run(["allow", "approved", "--policy", policy], env, project, "n\n")
        check("allow decline exits successfully", declined.returncode == 0, declined.stderr)
        check("allow decline writes no policy", not os.path.exists(policy))
        write(policy, "version: 1\nservers:\n  t:\n    tools: {}\n")
        p = run(["allow", "approved", "--policy", policy], env, project, "y\n")
        check("allow exits successfully", p.returncode == 0, p.stderr)
        check("allow shows the configured command", json.dumps(sys.executable) in p.stdout, p.stdout)
        check("allow writes the policy file", os.path.exists(policy))
        text = open(policy, encoding="utf-8").read() if os.path.exists(policy) else ""
        check("allow enables enforcement", "allowlist_enforced: true" in text, text)
        check("allow records a SHA-256", "sha256:" in text, text)
        check("allow records the exact args", json.dumps(PROFILE_SERVER) in text, text)
        check("allow preserves existing policy fields", "servers:" in text and "tools: {}" in text, text)
        valid = run(["policy", "validate", policy], env, project)
        check("allow output still validates", valid.returncode == 0, valid.stderr)

        s = Session(os.path.join(d, "state"), policy, sys.executable, [PROFILE_SERVER])
        r = s.start()
        check("approved server starts and answers tools/list", "result" in r, str(r)[:160])
        check("approved session exits cleanly", s.close() == 0)


def case_args_must_match():
    print("the allowlist matches the argument list, with optional wildcards")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        policy = os.path.join(d, "policy.yaml")
        write(policy, f"""version: 1
allowlist_enforced: true
allowlist:
  - name: "args"
    command: {json.dumps(sys.executable)}
    args:
      - {json.dumps(PROFILE_SERVER)}
""")
        exact = run(["--name", "t", "--state-dir", state, "--policy", policy,
                     "--", sys.executable, PROFILE_SERVER], dict(os.environ), d, "", timeout=15)
        check("exact args are allowed", exact.returncode == 0, exact.stderr[-300:])
        extra = run(["--name", "t", "--state-dir", state, "--policy", policy,
                     "--", sys.executable, PROFILE_SERVER, "--extra"], dict(os.environ), d, "", timeout=15)
        check("extra args are refused", extra.returncode == 2, f"rc={extra.returncode}")
        check("extra args refusal names SERVER_NOT_ALLOWED", "SERVER_NOT_ALLOWED" in extra.stderr, extra.stderr[-300:])

        write(policy, f"""version: 1
allowlist_enforced: true
allowlist:
  - name: "args"
    command: {json.dumps(sys.executable)}
    args: ["*"]
""")
        wildcard = run(["--name", "t", "--state-dir", state, "--policy", policy,
                        "--", sys.executable, PROFILE_SERVER], dict(os.environ), d, "", timeout=15)
        check("wildcard arg pattern is allowed", wildcard.returncode == 0, wildcard.stderr[-300:])


def case_allow_keeps_existing_hash():
    print("allow does not drop an existing hash when the command cannot be resolved")
    with tempfile.TemporaryDirectory() as d:
        home = os.path.join(d, "home")
        project = os.path.join(d, "project")
        os.makedirs(home)
        os.makedirs(project)
        env = dict(os.environ)
        env.update({"HOME": home, "USERPROFILE": home,
                    "APPDATA": os.path.join(d, "appdata"),
                    "XDG_CONFIG_HOME": os.path.join(d, "xdg")})
        missing = os.path.join(d, "missing-binary")
        write(os.path.join(home, ".claude.json"), json.dumps({"mcpServers": {
            "hashed": {"command": missing, "args": []},
        }}, indent=2) + "\n")
        policy = os.path.join(d, "policy.yaml")
        digest = "1" * 64
        write(policy, f"""version: 1
allowlist_enforced: true
allowlist:
  - name: "hashed"
    command: {json.dumps(missing)}
    args: []
    sha256: "{digest}"
""")
        p = run(["allow", "hashed", "--policy", policy, "--yes"], env, project)
        check("allow with a missing command exits successfully", p.returncode == 0, p.stderr)
        text = open(policy, encoding="utf-8").read()
        check("allow keeps the existing SHA-256", digest in text, text)


def case_changed_hash_refused():
    print("changed binary hash is refused")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        binary = os.path.join(d, "fake-binary")
        policy = os.path.join(d, "policy.yaml")
        write(binary, "version one\n")
        original = sha256_file(binary)
        write(policy, f"""version: 1
allowlist_enforced: true
allowlist:
  - name: "fake"
    command: {json.dumps(binary)}
    args: []
    sha256: "{original}"
""")
        write(binary, "version two\n")
        p = run(["--name", "t", "--state-dir", state, "--policy", policy,
                 "--", binary], dict(os.environ), d)
        check("changed binary exits 2", p.returncode == 2, f"rc={p.returncode}")
        check("changed binary refusal names SERVER_NOT_ALLOWED", "SERVER_NOT_ALLOWED" in p.stderr, p.stderr[-300:])
        check("changed binary refusal mentions SHA-256", "SHA-256" in p.stderr, p.stderr[-300:])
        audit = open(os.path.join(state, "audit-t.jsonl"), encoding="utf-8").read()
        check("changed binary is recorded", "SERVER_NOT_ALLOWED" in audit)
        check("changed binary never starts", '"event":"start"' not in audit)


def case_changed_lockfile_refused():
    print("changed package-lock hash is refused")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        lock = os.path.join(d, "package-lock.json")
        policy = os.path.join(d, "policy.yaml")
        write(lock, '{"lockfileVersion": 1}\n')
        original = sha256_file(lock)
        write(policy, f"""version: 1
allowlist_enforced: true
allowlist:
  - name: "locked"
    command: {json.dumps(sys.executable)}
    args:
      - {json.dumps(PROFILE_SERVER)}
    lockfile: {json.dumps(lock)}
    sha256: "{original}"
""")
        write(lock, '{"lockfileVersion": 2}\n')
        p = run(["--name", "t", "--state-dir", state, "--policy", policy,
                 "--", sys.executable, PROFILE_SERVER], dict(os.environ), d)
        check("changed lockfile exits 2", p.returncode == 2, f"rc={p.returncode}")
        check("changed lockfile refusal names SERVER_NOT_ALLOWED", "SERVER_NOT_ALLOWED" in p.stderr, p.stderr[-300:])


def case_install_prepopulates():
    print("install pre-populates the allowlist")
    with tempfile.TemporaryDirectory() as d:
        home = os.path.join(d, "home")
        project = os.path.join(d, "project")
        os.makedirs(home)
        os.makedirs(project)
        env = dict(os.environ)
        env.update({"HOME": home, "USERPROFILE": home,
                    "APPDATA": os.path.join(d, "appdata"),
                    "XDG_CONFIG_HOME": os.path.join(d, "xdg")})
        write(os.path.join(home, ".claude.json"), json.dumps({"mcpServers": {
            "installed": {"command": sys.executable, "args": [PROFILE_SERVER]},
        }}, indent=2) + "\n")
        p = run(["install", "--yes"], env, project)
        check("install exits successfully", p.returncode == 0, p.stderr)
        policy = os.path.join(home, ".sylenix-poc", "policy.yaml")
        check("install writes the default policy", os.path.exists(policy), policy)
        text = open(policy, encoding="utf-8").read() if os.path.exists(policy) else ""
        check("install enables allowlist enforcement", "allowlist_enforced: true" in text, text)
        check("install records the installed server", "installed" in text and json.dumps(PROFILE_SERVER) in text, text)

        allow2 = os.path.join(d, "allow2.yaml")
        p2 = run(["allow", "installed", "--policy", allow2, "--yes"], env, project)
        check("allow reads an already wrapped config", p2.returncode == 0, p2.stderr)
        text2 = open(allow2, encoding="utf-8").read() if os.path.exists(allow2) else ""
        check("allow unwraps the Guard command",
              json.dumps(sys.executable) in text2 and json.dumps(GUARD) not in text2, text2)

        s = Session(os.path.join(d, "state"), policy, sys.executable, [PROFILE_SERVER])
        r = s.start()
        check("pre-populated server starts", "result" in r, str(r)[:160])
        check("install allowlist session exits cleanly", s.close() == 0)


def case_install_custom_paths():
    print("install pins custom policy and state paths in the wrapper")
    with tempfile.TemporaryDirectory() as d:
        home = os.path.join(d, "home")
        project = os.path.join(d, "project")
        os.makedirs(home)
        os.makedirs(project)
        env = dict(os.environ)
        env.update({"HOME": home, "USERPROFILE": home,
                    "APPDATA": os.path.join(d, "appdata"),
                    "XDG_CONFIG_HOME": os.path.join(d, "xdg")})
        cfg = os.path.join(home, ".claude.json")
        write(cfg, json.dumps({"mcpServers": {
            "custom": {"command": sys.executable, "args": [PROFILE_SERVER]},
        }}, indent=2) + "\n")
        policy = os.path.join(d, "custom-policy", "policy.yaml")
        state = os.path.join(d, "custom-state")
        p = run(["install", "--yes", "--policy", policy, "--state-dir", state], env, project)
        check("custom install exits successfully", p.returncode == 0, p.stderr)
        check("custom install writes the custom policy", os.path.exists(policy), policy)
        entry = json.load(open(cfg, encoding="utf-8"))["mcpServers"]["custom"]
        wrapper = entry.get("args", [])
        check("custom install pins --policy", f"--policy={policy}" in wrapper, str(wrapper))
        check("custom install pins --state-dir", f"--state-dir={state}" in wrapper, str(wrapper))

        approved = run(list(wrapper), env, project, "", timeout=15)
        check("custom wrapper starts the approved server", approved.returncode == 0, approved.stderr[-300:])

        separator = wrapper.index("--")
        unapproved = wrapper[:separator + 1] + [sys.executable, "-c", "print('nope')"]
        refused = run(unapproved, env, project, "", timeout=15)
        check("custom wrapper enforces the custom policy",
              refused.returncode == 2 and "SERVER_NOT_ALLOWED" in refused.stderr,
              refused.stderr[-300:])

        u = run(["uninstall", "--yes"], env, project)
        check("custom uninstall exits successfully", u.returncode == 0, u.stderr)
        restored = json.load(open(cfg, encoding="utf-8"))["mcpServers"]["custom"]
        check("custom uninstall restores the original command",
              restored.get("command") == sys.executable, str(restored))
        check("custom uninstall drops the wrapper flags",
              restored.get("args") == [PROFILE_SERVER], str(restored))


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    case_unapproved_refused()
    case_allow_and_start()
    case_args_must_match()
    case_allow_keeps_existing_hash()
    case_changed_hash_refused()
    case_changed_lockfile_refused()
    case_install_prepopulates()
    case_install_custom_paths()
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
