"""Protocol self-test for sylenix-guard. Needs only Python 3 and the built binary.

    python demo/selftest.py            # expects ./bin/sylenix-guard

Each case starts a fresh guard in front of demo/fake_server.py, so every case
begins with a clean session. These tests check the proxy's behaviour; they do
not measure whether it stops a real agent (that is demo/harness.py).
"""
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(ROOT, "bin", "sylenix-guard")
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
    def __init__(self, state_dir, extra_flags=(), env=None):
        e = dict(os.environ)
        e.update(env or {})
        cmd = [GUARD, "--name", "t", "--state-dir", state_dir, "--readonly", "read_ticket",
               *extra_flags, "--", sys.executable, FAKE]
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

    def recv(self, timeout=10, raw=False):
        line = self.q.get(timeout=timeout)
        if line is None or raw:
            return line
        return json.loads(line)

    def call(self, name, args=None):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv()

    def start(self):
        self.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
        self.recv()
        self.raw(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.send("tools/list")
        return self.recv()

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            return self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None


def rule(resp):
    return (resp.get("error") or {}).get("data", {}).get("rule")


def case_taint_flow():
    print("taint latch, default deny, read-only allowlist, datamarking")
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "calls.log")
        s = Session(d, env={"FAKE_CALL_LOG": log})
        s.start()
        r = s.call("write_file")
        check("clean session: write_file allowed", "result" in r)
        r = s.call("read_ticket")
        txt = r["result"]["content"][0]["text"]
        check("read_ticket result is datamarked", txt.startswith("<untrusted_tool_result"), txt[:60])
        check("closing tag in payload is neutralized", txt.count("</untrusted_tool_result>") == 1)
        check("zero-width characters stripped from payload", "\u200b" not in txt)
        r = s.call("write_file")
        check("tainted session: write_file blocked with -32000", r.get("error", {}).get("code") == -32000 and rule(r) == "TAINT_SINK", str(r))
        check("blocked call echoes the request id", r.get("id") == s._id)
        r = s.call("some_unmapped_tool")
        check("unmapped tool is blocked when tainted", rule(r) == "TAINT_SINK", str(r))
        r = s.call("read_ticket")
        check("read-only tool still allowed when tainted", "result" in r)
        code = s.close()
        calls = open(log).read().split()
        check("blocked calls never reached the server", calls == ["write_file", "read_ticket", "read_ticket"], str(calls))
        check("clean exit when the host closes stdin", code == 0, str(code))


def case_pin_persistence():
    print("manifest pinning across restarts")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.start()
        s.close()
        check("pin file written", os.path.exists(os.path.join(d, "pins-t.json")))
        s = Session(d, env={"FAKE_DESC_V2": "1"})
        s.start()
        r = s.call("write_file")
        check("changed definition is quarantined (-32001)", r.get("error", {}).get("code") == -32001, str(r))
        s.close()
        audit = open(os.path.join(d, "audit-t.jsonl")).read()
        check("audit log records the quarantine", "tool_quarantined" in audit)
        check("audit log holds no argument values", "arguments" not in audit)


def case_invisible():
    print("hidden characters in a tool definition")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, env={"FAKE_INVISIBLE": "1"})
        s.start()
        r = s.call("write_file")
        check("tool with zero-width character is quarantined", r.get("error", {}).get("code") == -32001, str(r))
        s.close()


def case_noisy():
    print("non-JSON output from the server")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.start()
        s.send("tools/call", {"name": "noisy", "arguments": {}})
        junk = s.recv(raw=True)  # the junk line passes through untouched
        check("junk line is forwarded unchanged", junk.strip() == b"DEBUG: this is not JSON-RPC", str(junk))
        s.recv()  # the real response
        r = s.call("write_file")
        check("junk on stdout latches taint", rule(r) == "TAINT_SINK", str(r))
        s.close()


def case_bad_input():
    print("malformed and batch frames from the host")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.start()
        s.raw("this is not json")
        r = s.recv()
        check("garbage line gets -32700 with id null", r["error"]["code"] == -32700 and r["id"] is None, str(r))
        s.raw('[{"jsonrpc":"2.0","id":1,"method":"ping"}]')
        r = s.recv()
        check("batch frame is refused, not forwarded", r["error"]["code"] == -32600, str(r))
        s.send("ping")
        r = s.recv()
        check("connection still works afterwards", "result" in r, str(r))
        s.close()


def case_large_frame():
    print("large frames")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, extra_flags=("--trust", "big"))
        s.start()
        r = s.call("big")
        check("3 MB result arrives intact", len(r["result"]["content"][0]["text"]) == 3 * 1024 * 1024)
        s.close()


def case_interleaving():
    print("stdout stays valid under concurrent blocked calls and forwarded calls")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.start()
        s.call("read_ticket")  # taint the session
        n = 300
        for _ in range(n):
            s.send("tools/call", {"name": "write_file", "arguments": {}})  # blocked by the guard
            s.send("ping")                                                 # answered by the server
        ok, bad = 0, 0
        for _ in range(2 * n):
            try:
                s.recv()
                ok += 1
            except Exception:
                bad += 1
        check(f"all {2 * n} replies parsed as valid JSON", ok == 2 * n and bad == 0, f"ok={ok} bad={bad}")
        s.close()


def case_dialog_fails_closed():
    print("approval dialog unavailable")
    import shutil
    if sys.platform != "linux" or shutil.which("zenity"):
        print("  skip (a real dialog would appear on this machine)")
        return
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, extra_flags=("--approve", "dialog"))
        s.start()
        s.call("read_ticket")
        r = s.call("write_file")
        check("no dialog available means denied (-32002)", r.get("error", {}).get("code") == -32002, str(r))
        s.close()


if __name__ == "__main__":
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    t0 = time.time()
    for fn in (case_taint_flow, case_pin_persistence, case_invisible, case_noisy,
               case_bad_input, case_large_frame, case_interleaving, case_dialog_fails_closed):
        fn()
    print(f"\n{passed} passed, {len(failed)} failed in {time.time() - t0:.1f}s")
    sys.exit(1 if failed else 0)
