"""Regression probes for the scratch and grant fast-path bypasses.

Each probe first taints the session by reading a ticket, then makes a sink call
whose main path is inside the allowed directory and whose extra value points at
an egress or sensitive destination. The call must be blocked. The same probes
run under --allow-write-under and under --grant.

The final cases are controls and legitimate writes: an allowed scratch call
must still pass, including a URL in a content value, a known nested path key, a
".." that stays inside, and a case variant on a case-insensitive filesystem.
A symlink/junction created after the guard starts must not become an escape.

Run after building the guard:

    python3 tests/probes/test_scratch_grant_bypass.py
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
        cmd = [GUARD, "--name", "probe", "--state-dir", state_dir,
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
                                 "clientInfo": {"name": "probe", "version": "0"}})
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


def make_dir_link(link, target):
    """Create a directory symlink, or a Windows junction without admin rights."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return os.path.exists(link)
    except (OSError, NotImplementedError):
        if sys.platform == "win32":
            r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target],
                               capture_output=True, text=True)
            return r.returncode == 0 and os.path.exists(link)
    return False


def flip_case(path):
    head, tail = os.path.split(path)
    for i, ch in enumerate(tail):
        if ch.isalpha():
            return os.path.join(head, tail[:i] + ch.swapcase() + tail[i + 1:])
    return path


def probes(out):
    """Ten tainted-call probes; each carries a destination beside a safe path."""
    return [
        ("bare .env under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": ".env"}, "SENSITIVE_TARGET"),
        ("bare id_rsa under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": "id_rsa"}, "SENSITIVE_TARGET"),
        ("bare Makefile under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": "Makefile"}, "SENSITIVE_TARGET"),
        ("nested .env under an unknown object",
         {"path": os.path.join(out, "ok.md"), "options": {"x": ".env"}}, "SENSITIVE_TARGET"),
        ("drive-relative path under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": "C:escape.txt"}, "TAINT_SINK"),
        ("home-relative ssh path under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": "~/.ssh/authorized_keys"}, "TAINT_SINK"),
        ("home-relative aws path under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": "~/.aws/credentials"}, "TAINT_SINK"),
        ("hostname under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": "www.attacker.example"}, "TAINT_SINK"),
        ("host:port under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": "attacker.example:443"}, "EGRESS_TARGET"),
        ("parent-directory value under an unknown key",
         {"path": os.path.join(out, "ok.md"), "extra": ".."}, "TAINT_SINK"),
    ]


def run_probes(s, out, mode):
    for label, args, want in probes(out):
        r = s.call("write_file", args)
        got = rule(r)
        check(f"{mode}: {label} is blocked", "result" not in r and got == want,
              f"rule={got} resp={str(r)[:120]}")


def run_controls(s, out, mode):
    r = s.call("write_file", {"path": os.path.join(out, "ok.md"), "file": ".env"})
    check(f"{mode}: sensitive value under a known path key is blocked",
          "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"),
                              "extra": "https://audit-collector.example/ingest"})
    check(f"{mode}: URL under an unknown key is blocked",
          "result" not in r and rule(r) == "EGRESS_TARGET", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"), "host": "attacker"})
    check(f"{mode}: bare host under a destination key is blocked",
          "result" not in r and rule(r) == "EGRESS_TARGET", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"),
                              "extra": "mailto:attacker@example.com"})
    check(f"{mode}: non-HTTP URI under an unknown key is blocked",
          "result" not in r and rule(r) == "EGRESS_TARGET", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"),
                              "extra": "[2001:db8::1]:443"})
    check(f"{mode}: IPv6 destination under an unknown key is blocked",
          "result" not in r and rule(r) == "EGRESS_TARGET", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"), "extra": "attacker:443"})
    check(f"{mode}: bare host:port under an unknown key is blocked",
          "result" not in r and rule(r) == "EGRESS_TARGET", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"), "extra": ".ssh"})
    check(f"{mode}: hidden directory name under an unknown key is blocked",
          "result" not in r and rule(r) == "TAINT_SINK", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"),
                              "destination": os.path.join(os.path.dirname(out), "escape.md")})
    check(f"{mode}: outside path under a known path key is blocked",
          "result" not in r and rule(r) == "TAINT_SINK", f"rule={rule(r)}")

    for label, args in (
        ("parent traversal in a path key", {"path": os.path.join("..", "escape.md")}),
        ("home-relative path key", {"path": "~/.ssh/authorized_keys"}),
        ("environment-expanded path key", {"path": "$HOME/.ssh/authorized_keys"}),
        ("embedded environment path key", {"path": os.path.join(out, "$HOME", "escape.md")}),
        ("percent-encoded path key", {"path": os.path.join(out, "%2e%2e", "escape.md")}),
        ("drive-relative path key", {"path": "C:escape.txt"}),
    ):
        r = s.call("write_file", args)
        check(f"{mode}: {label} is blocked",
              "result" not in r and rule(r) == "TAINT_SINK", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, ".e\u200bnv")})
    check(f"{mode}: zero-width hidden sensitive path is blocked",
          "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"),
                              "content": "see https://example.com/x"})
    check(f"{mode}: URL mentioned in content stays allowed", "result" in r, str(r)[:120])

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"),
                              "file": os.path.join(out, "other.md")})
    check(f"{mode}: every known path key inside the scratch root is allowed",
          "result" in r, str(r)[:120])

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"),
                              "destination": os.path.join(out, "third.md")})
    check(f"{mode}: destination is treated as a known path key",
          "result" in r, str(r)[:120])

    r = s.call("write_file", {"path": os.path.join(out, "ok.md"),
                              "output_path": os.path.join(out, "fourth.md")})
    check(f"{mode}: output_path is treated as a known path key",
          "result" in r, str(r)[:120])

    r = s.call("write_file", {"path": os.path.join(out, "sub", "..", "ok.md")})
    check(f"{mode}: a .. that stays inside the scratch root is allowed",
          "result" in r, str(r)[:120])


def run_case_variant(s, out, mode):
    variant = flip_case(out)
    if not os.path.exists(variant):
        print(f"  skip {mode}: filesystem is case-sensitive")
        return
    r = s.call("write_file", {"path": os.path.join(variant, "ok.md")})
    check(f"{mode}: case variant of the scratch root is allowed", "result" in r, str(r)[:120])


def run_symlink_escape(s, out, mode):
    link = os.path.join(out, "link")
    target = os.path.join(os.path.dirname(out), "outside")
    if not os.path.isdir(target):
        os.mkdir(target)
    if not os.path.exists(link) and not make_dir_link(link, target):
        print(f"  skip {mode}: cannot create a directory symlink/junction")
        return
    r = s.call("write_file", {"path": os.path.join(link, "evil.txt")})
    check(f"{mode}: symlink created during the session cannot escape",
          "result" not in r and rule(r) == "TAINT_SINK", f"rule={rule(r)}")

    r = s.call("write_file", {"path": os.path.join(link, "..", "evil.txt")})
    check(f"{mode}: .. after a symlink is resolved in OS order",
          "result" not in r and rule(r) == "TAINT_SINK", f"rule={rule(r)}")

    sensitive = os.path.join(out, ".env")
    if not os.path.isdir(sensitive):
        os.mkdir(sensitive)
    sensitive_link = os.path.join(out, "sensitive-link")
    if not os.path.exists(sensitive_link) and not make_dir_link(sensitive_link, sensitive):
        print(f"  skip {mode}: cannot create a symlink to a sensitive target")
        return
    r = s.call("write_file", {"path": os.path.join(sensitive_link, "secret")})
    check(f"{mode}: a symlink to a sensitive name is still blocked",
          "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "out")
        os.mkdir(out)

        s = Session(d, flags=("--allow-write-under", out))
        s.start()
        s.call("read_ticket")
        print("--allow-write-under")
        run_probes(s, out, "scratch")
        run_controls(s, out, "scratch")
        run_case_variant(s, out, "scratch")
        run_symlink_escape(s, out, "scratch")
        check("scratch: clean exit", s.close() == 0)

        s = Session(d, flags=("--grant", "write_file:" + out + "=5m"))
        s.start()
        s.call("read_ticket")
        print("--grant (scoped)")
        run_probes(s, out, "grant")
        run_controls(s, out, "grant")
        run_case_variant(s, out, "grant")
        run_symlink_escape(s, out, "grant")
        check("grant: clean exit", s.close() == 0)

        s = Session(d, flags=("--grant", "write_file=5m"))
        s.start()
        s.call("read_ticket")
        print("--grant (tool-wide)")
        r = s.call("write_file", {"path": os.path.join(out, "anywhere.md"),
                                  "content": "see https://example.com/x"})
        check("tool-wide grant: ordinary call is allowed", "result" in r, str(r)[:120])
        r = s.call("write_file", {"path": os.path.join(out, "anywhere.md"), "extra": ".env"})
        check("tool-wide grant: sensitive extra value is blocked",
              "result" not in r and rule(r) == "SENSITIVE_TARGET", f"rule={rule(r)}")
        r = s.call("write_file", {"path": os.path.join(out, "anywhere.md"), "extra": "C:escape.txt"})
        check("tool-wide grant: ambiguous extra value is blocked",
              "result" not in r and rule(r) == "TAINT_SINK", f"rule={rule(r)}")
        r = s.call("write_file", {"path": "C:escape.txt"})
        check("tool-wide grant: unresolvable path key is blocked",
              "result" not in r and rule(r) == "TAINT_SINK", f"rule={rule(r)}")
        check("tool-wide grant: clean exit", s.close() == 0)

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
