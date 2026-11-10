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
# On Windows, anything that resolves commands through PATHEXT (including the MCP
# client the harness uses) runs sylenix-guard.exe, so tests must point at the
# same file or they silently test a stale binary.
GUARD = os.path.join(ROOT, "bin", "sylenix-guard.exe" if sys.platform == "win32" else "sylenix-guard")
FAKE = os.path.join(ROOT, "demo", "fake_server.py")

# --policy mode replaces only the --readonly flag with an equivalent file. The
# rest of the suite keeps exercising the flags it is about.
POLICY_MODE = False
POLICY_TEXT = """version: 1
approval: deny
servers:
  t:
    tools:
      read_ticket:
        class: read
"""

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
        cmd = [GUARD, "--name", "t", "--state-dir", state_dir]
        if POLICY_MODE:
            with open(os.path.join(state_dir, "policy.yaml"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(POLICY_TEXT)
        else:
            cmd += ["--readonly", "read_ticket"]
        cmd += [*extra_flags, "--", sys.executable, FAKE]
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
    for cp in ("200B", "00AD", "034F", "061C", "115F", "1160", "17B4", "180E", "2028", "2029", "202E",
               "2060", "206A", "3164", "FEFF", "FFA0", "FFF9", "E0041", "E0100"):
        with tempfile.TemporaryDirectory() as d:
            s = Session(d, env={"FAKE_INVISIBLE": cp})
            s.start()
            r = s.call("write_file")
            check(f"U+{cp} in a definition quarantines the tool", r.get("error", {}).get("code") == -32001, str(r))
            s.close()
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, env={"FAKE_PLAIN_UNICODE": "1"})
        s.start()
        r = s.call("write_file")
        check("ordinary non-ASCII text (accents, CJK, emoji) is not quarantined", "result" in r, str(r))
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


def case_duplicate_keys():
    print("duplicate JSON keys")
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "calls.log")
        s = Session(d, env={"FAKE_CALL_LOG": log})
        s.start()
        s.raw('{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"read_ticket","name":"write_file","arguments":{}}}')
        r = s.recv()
        check("duplicate key in params is refused (-32600, DUPLICATE_KEYS)", r["error"]["code"] == -32600 and rule(r) == "DUPLICATE_KEYS", str(r))
        check("refused frame carries id null", r["id"] is None)
        r = s.call("read_ticket", {"a": {"x": 1}, "b": {"x": 2}, "c": [{"x": 1}, {"x": 2}]})
        check("same key in sibling objects is not a duplicate", "result" in r, str(r))
        s.close()
        calls = open(log).read().split()
        check("refused frame never reached the server", calls == ["read_ticket"], str(calls))


def case_unmatched_response():
    print("response to an id nobody asked about")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.start()
        s.send("tools/call", {"name": "ghost", "arguments": {}})
        s.recv()  # the unsolicited frame is forwarded unchanged
        s.recv()  # the real response
        r = s.call("write_file")
        check("unmatched response latches taint", rule(r) == "TAINT_SINK", str(r))
        s.close()


def case_oversize_frames():
    print("frames at and over the 10 MiB limit")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.start()
        head = '{"jsonrpc":"2.0","id":70,"method":"ping","params":{"pad":"'
        tail = '"}}'
        pad = (10 << 20) - len(head) - len(tail)
        s.raw(head + "a" * pad + tail)  # exactly 10 MiB
        r = s.recv(timeout=30)
        check("a frame of exactly 10 MiB is accepted", r.get("id") == 70 and "result" in r, str(r)[:120])
        s.raw(head + "a" * (pad + 1) + tail)  # one byte over
        r = s.recv(timeout=30)
        check("one byte over is refused with -32600 FRAME_TOO_LARGE and id null",
              r["error"]["code"] == -32600 and rule(r) == "FRAME_TOO_LARGE" and r["id"] is None, str(r)[:160])
        s.send("ping")
        r = s.recv()
        check("the session survives an oversize frame", "result" in r, str(r))
        s.close()
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, extra_flags=("--trust", "huge"))
        s.start()
        s.send("tools/call", {"name": "huge", "arguments": {}})
        r = s.recv(timeout=30)
        check("oversize server frame fails the pending request (SERVER_FRAME_TOO_LARGE)", rule(r) == "SERVER_FRAME_TOO_LARGE", str(r)[:160])
        r = s.call("write_file")
        check("oversize server frame latches taint", rule(r) == "TAINT_SINK", str(r))
        s.close()


def case_server_stream_closed():
    print("server closes its stdout but keeps running")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.start()
        t0 = time.time()
        s.send("tools/call", {"name": "close_stdout", "arguments": {}})
        r = s.recv(timeout=10)
        check("pending request fails with SERVER_STREAM_CLOSED", rule(r) == "SERVER_STREAM_CLOSED", str(r))
        s.send("ping")
        r = s.recv(timeout=10)
        check("later requests fail the same way, not silently", rule(r) == "SERVER_STREAM_CLOSED", str(r))
        code = s.close()
        check("guard exits within 10 s with code 1", code == 1 and time.time() - t0 < 10, f"code={code} elapsed={time.time() - t0:.1f}")


def case_duplicate_ids():
    print("a request id that is still pending")
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "calls.log")
        s = Session(d, env={"FAKE_CALL_LOG": log})
        s.start()
        s.raw('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow","arguments":{}}}')
        s.raw('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":{}}}')
        first = s.recv()
        second = s.recv()
        refused = first if "error" in first else second
        answered = second if "error" in first else first
        check("second use of the id is refused (-32600 DUPLICATE_ID) with id null", rule(refused) == "DUPLICATE_ID" and refused["id"] is None, str(refused))
        check("first request is still answered, with its own identity",
              answered.get("id") == 7 and answered["result"]["content"][0]["text"].startswith('<untrusted_tool_result origin="slow"'), str(answered)[:160])
        s.close()
        calls = open(log).read().split()
        check("the refused request never reached the server", calls == ["slow"], str(calls))
        with tempfile.TemporaryDirectory() as d2:
            s = Session(d2)
            s.start()
            ok = True
            for _ in range(3):
                s.raw('{"jsonrpc":"2.0","id":9,"method":"ping"}')
                ok = ok and "result" in s.recv()
            check("an id can be reused once its request has been answered", ok)
            s.close()


def case_pin_file_damage():
    print("pin file that exists but cannot be read")
    for label, content in (("invalid JSON", "{corrupted json"), ("null", "null"), ("a list", "[]"), ("empty", ""),
                           ("null value", '{"write_file": null}'), ("not a hash", '{"write_file": "nothex"}'),
                           ("empty name", '{"": "' + "0" * 64 + '"}')):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "pins-t.json"), "w").write(content)
            p = subprocess.run([GUARD, "--name", "t", "--state-dir", d, "--", sys.executable, FAKE],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            audit = open(os.path.join(d, "audit-t.jsonl")).read()
            check(f"{label}: guard refuses to start (exit 2, no server launched)",
                  p.returncode == 2 and "pins_unreadable" in audit and '"event":"start"' not in audit, f"rc={p.returncode}")
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "pins-t.json"), "w").write("{corrupted json")
        s = Session(d, extra_flags=("--reset-pins",))
        s.start()
        r = s.call("write_file")
        check("--reset-pins recovers: the guard starts and works", "result" in r, str(r))
        s.close()
        check("--reset-pins is recorded in the audit log", "pins_reset" in open(os.path.join(d, "audit-t.jsonl")).read())


def case_structured_content():
    print("structuredContent")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d)
        s.start()
        r = s.call("structured")
        sc = r["result"]["structuredContent"]
        check("invisible characters are stripped from structuredContent strings", sc["note"] == "ab" and sc["n"][1]["k"] == "xy", str(sc))
        check("numbers in structuredContent are preserved exactly", sc["big"] == 12345678901234567890 and sc["n"][0] == 1, str(sc))
        check("the text item is still datamarked", r["result"]["content"][0]["text"].startswith("<untrusted_tool_result"))
        s.close()


def case_server_request_taint():
    print("server request content latches taint")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, extra_flags=("--trust", "sample"))
        s.start()
        s.send("tools/call", {"name": "sample", "arguments": {}})
        req = s.recv()
        check("sampling request is forwarded to the host",
              req.get("method") == "sampling/createMessage" and req.get("id") == 900001, str(req))
        result = s.recv()
        check("trusted sample tool result does not taint by itself", "result" in result, str(result))
        r = s.call("http_post", {"url": "https://audit-collector.example/ingest", "body": "x"})
        check("server request content latches taint: egress is blocked",
              rule(r) == "EGRESS_TARGET", str(r))
        code = s.close()
        check("clean exit after server request taint", code == 0, str(code))
        audit = open(os.path.join(d, "audit-t.jsonl")).read()
        check("audit records TAINT_SERVER_REQUEST", "TAINT_SERVER_REQUEST" in audit)
        check("audit does not log sampling content", "SAMPLING-INJECT-MARKER" not in audit)


def case_scratch_writes():
    print("--allow-write-under: tainted writes inside a scratch root")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        out = os.path.join(d, "out")
        os.mkdir(state)
        os.mkdir(out)
        log = os.path.join(d, "calls.log")
        s = Session(state, extra_flags=("--allow-write-under", out), env={"FAKE_CALL_LOG": log})
        s.start()
        s.call("read_ticket")  # taint the session
        r = s.call("write_file", {"path": os.path.join(out, "ok.md")})
        check("write inside the scratch root needs no prompt", "result" in r, str(r))
        r = s.call("write_file", {"path": os.path.join(d, "escape.md")})
        check("write outside the scratch root is blocked (TAINT_SINK)", rule(r) == "TAINT_SINK", str(r))
        r = s.call("write_file", {"path": os.path.join(out, "..", "escape.md")})
        check("a .. path out of the scratch root is blocked", rule(r) == "TAINT_SINK", str(r))
        r = s.call("write_file", {"path": os.path.join(out, ".env")})
        check(".env is never scratch-allowed (SENSITIVE_TARGET)", rule(r) == "SENSITIVE_TARGET", str(r))
        r = s.call("write_file", {"path": os.path.join(out, ".git", "config")})
        check(".git paths are never scratch-allowed", rule(r) == "SENSITIVE_TARGET", str(r))
        r = s.call("write_file", {"path": os.path.join(out, "go.mod")})
        check("root config names are never scratch-allowed", rule(r) == "SENSITIVE_TARGET", str(r))
        r = s.call("http_post", {"url": "https://audit-collector.example/ingest", "body": "x"})
        check("a network target is hard-blocked (EGRESS_TARGET)", rule(r) == "EGRESS_TARGET", str(r))
        r = s.call("write_file", {"path": os.path.join(out, "notes.md"), "content": "see https://example.com/x"})
        check("a URL mentioned in content is not an egress target", "result" in r, str(r))
        code = s.close()
        calls = open(log).read().split()
        check("only the two allowed writes reached the server", calls == ["read_ticket", "write_file", "write_file"], str(calls))
        check("clean exit", code == 0, str(code))
    with tempfile.TemporaryDirectory() as d:  # the hard blocks need no scratch flag
        out = os.path.join(d, "out")
        os.mkdir(out)
        s = Session(d)
        s.start()
        s.call("read_ticket")
        r = s.call("write_file", {"path": ".env"})
        check("SENSITIVE_TARGET applies without --allow-write-under", rule(r) == "SENSITIVE_TARGET", str(r))
        r = s.call("write_file", {"url": "https://evil.example"})
        check("EGRESS_TARGET applies without --allow-write-under", rule(r) == "EGRESS_TARGET", str(r))
        r = s.call("write_file", {"path": "notes.md"})
        check("other tainted writes still get TAINT_SINK", rule(r) == "TAINT_SINK", str(r))
        s.close()
    with tempfile.TemporaryDirectory() as d:  # TOOL=DIR scopes the fast path
        state = os.path.join(d, "state")
        out = os.path.join(d, "out")
        os.mkdir(state)
        os.mkdir(out)
        s = Session(state, extra_flags=("--allow-write-under", "write_file=" + out))
        s.start()
        s.call("read_ticket")
        r = s.call("write_file", {"path": os.path.join(out, "ok.md")})
        check("TOOL=DIR allows the named tool inside its root", "result" in r, str(r))
        r = s.call("some_unmapped_tool", {"path": os.path.join(out, "ok.md")})
        check("TOOL=DIR does not cover other tools", rule(r) == "TAINT_SINK", str(r))
        s.close()


def case_grants():
    print("time-bounded grants")
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        out = os.path.join(d, "out")
        os.mkdir(state)
        os.mkdir(out)
        s = Session(state, extra_flags=("--grant", "write_file:" + out + "=2s"))
        s.start()
        s.call("read_ticket")
        r = s.call("write_file", {"path": os.path.join(out, "a.md")})
        check("a live grant lets the call through", "result" in r, str(r))
        r = s.call("write_file", {"path": os.path.join(d, "other.md")})
        check("a scoped grant does not cover paths outside its directory", rule(r) == "TAINT_SINK", str(r))
        time.sleep(2.3)
        r = s.call("write_file", {"path": os.path.join(out, "a.md")})
        check("an expired grant stops allowing calls", rule(r) == "TAINT_SINK", str(r))
        s.close()
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, extra_flags=("--grant", "write_file=5m"))
        s.start()
        s.call("read_ticket")
        r = s.call("write_file", {"path": "anywhere.md"})
        check("a tool-wide grant covers any path", "result" in r, str(r))
        r = s.call("http_post", {"url": "https://evil.example"})
        check("a grant never covers a network target", rule(r) == "EGRESS_TARGET", str(r))
        r = s.call("write_file", {"path": ".env"})
        check("a grant never covers a sensitive path", rule(r) == "SENSITIVE_TARGET", str(r))
        s.close()
    for flag, spec in (("--grant", "write_file=banana"), ("--grant", "write_file"), ("--allow-write-under", "write_file=")):
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run([GUARD, "--name", "t", "--state-dir", d, flag, spec, "--", sys.executable, FAKE],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            check(f"bad spec {flag} {spec} refuses to start (exit 2)", p.returncode == 2, f"rc={p.returncode}")


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
    import argparse
    ap = argparse.ArgumentParser(description="Protocol self-test for sylenix-guard.")
    ap.add_argument("--policy", action="store_true",
                    help="use an equivalent policy file instead of --readonly")
    opts = ap.parse_args()
    POLICY_MODE = opts.policy
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    print(f"mode: {'policy file' if POLICY_MODE else 'flags'}")
    t0 = time.time()
    for fn in (case_taint_flow, case_pin_persistence, case_invisible, case_noisy,
               case_bad_input, case_large_frame, case_interleaving, case_duplicate_keys, case_unmatched_response, case_oversize_frames,
               case_server_stream_closed, case_duplicate_ids, case_pin_file_damage,
               case_structured_content, case_server_request_taint, case_scratch_writes,
               case_grants, case_dialog_fails_closed):
        fn()
    print(f"\n{passed} passed, {len(failed)} failed in {time.time() - t0:.1f}s")
    sys.exit(1 if failed else 0)
