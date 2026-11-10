"""Integration probes for the Streamable HTTP proxy.

The same tool-call sequence is sent through the stdio proxy (demo/fake_server.py)
and through the HTTP proxy (tests/probes/http_fake_server.py). The blocked
calls must produce the same JSON-RPC code and rule on both transports.

Also covers POST SSE responses, server notifications over SSE, the optional GET
SSE stream, MCP session IDs, DELETE session termination, auth-header pass-through,
pin persistence and quarantine, and the rule that tokens are never written to the
state directory.

Protocol target: MCP 2025-11-25 Streamable HTTP (the revision with sessions and
GET SSE). The proxy forwards session headers only when present, so it also works
with the stateless 2026-07-28 shape.

Run after building the guard:
    python3 tests/probes/test_http_proxy.py
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

from http_fake_server import FakeHTTPMCP

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GUARD = os.environ.get("SYLENIX_GUARD") or os.path.join(
    ROOT, "bin", "sylenix-guard.exe" if sys.platform == "win32" else "sylenix-guard")
STDIO_FAKE = os.path.join(ROOT, "demo", "fake_server.py")

passed, failed = 0, []


def check(label, cond, detail=""):
    global passed
    if cond:
        passed += 1
        print(f"  ok   {label}")
    else:
        failed.append(label)
        print(f"  FAIL {label} {detail}")


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, proc):
    deadline = time.time() + 10
    while time.time() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"guard proxy exited early: {err}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("guard proxy did not start listening")


def stop_process(proc):
    if proc is None:
        return
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    if proc.stderr:
        try:
            proc.stderr.close()
        except Exception:
            pass


def start_proxy(state_dir, upstream, extra_flags=()):
    port = free_port()
    cmd = [
        GUARD, "proxy",
        "--name", "t",
        "--state-dir", state_dir,
        "--readonly", "read_ticket",
        "--approve", "deny",
        "--listen", f"127.0.0.1:{port}",
        "--upstream", upstream,
        *extra_flags,
    ]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(os.environ),
    )
    wait_port(port, proc)
    return proc, port


class HTTPClient:
    def __init__(self, port, token=None):
        self.port = port
        self.token = token
        self.session = None
        self.next_id = 0

    def _headers(self, accept="application/json, text/event-stream"):
        headers = {"Content-Type": "application/json", "Accept": accept}
        if self.token:
            headers["Authorization"] = self.token
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return headers

    def _connect(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)

    def post(self, obj):
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        conn = self._connect()
        try:
            conn.request("POST", "/mcp", body=body, headers=self._headers())
            resp = conn.getresponse()
            sid = resp.getheader("Mcp-Session-Id")
            if sid:
                self.session = sid
            ctype = (resp.getheader("Content-Type") or "").lower()
            if ctype.startswith("text/event-stream"):
                return resp.status, self._read_sse(resp), ctype
            data = resp.read()
            return resp.status, (json.loads(data.decode("utf-8")) if data else None), ctype
        finally:
            conn.close()

    def get_stream(self):
        conn = self._connect()
        try:
            conn.request("GET", "/mcp", headers=self._headers("text/event-stream"))
            resp = conn.getresponse()
            sid = resp.getheader("Mcp-Session-Id")
            if sid:
                self.session = sid
            return resp.status, self._read_sse(resp)
        finally:
            conn.close()

    def delete(self):
        conn = self._connect()
        try:
            conn.request("DELETE", "/mcp", headers=self._headers())
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, data
        finally:
            conn.close()

    @staticmethod
    def _read_sse(resp):
        events = []
        fields = {}
        while True:
            line = resp.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if text == "":
                if fields:
                    events.append(fields)
                    fields = {}
                continue
            if text.startswith(":"):
                continue
            if ":" in text:
                key, value = text.split(":", 1)
                if value.startswith(" "):
                    value = value[1:]
            else:
                key, value = text, ""
            if key == "data":
                fields.setdefault("data", []).append(value)
            else:
                fields[key] = value
        if fields:
            events.append(fields)
        out = []
        for ev in events:
            if "data" in ev:
                ev["data"] = "\n".join(ev["data"])
            out.append(ev)
        return out

    def initialize(self):
        self.next_id += 1
        return self.post({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "http-probe", "version": "0"},
            },
        })

    def initialized(self):
        return self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self):
        self.next_id += 1
        return self.post({"jsonrpc": "2.0", "id": self.next_id, "method": "tools/list"})

    def call(self, name, args=None):
        self.next_id += 1
        rid = self.next_id
        status, body, ctype = self.post({
            "jsonrpc": "2.0",
            "id": rid,
            "method": "tools/call",
            "params": {"name": name, "arguments": args or {}},
        })
        if isinstance(body, list):
            chosen = None
            for ev in body:
                try:
                    msg = json.loads(ev.get("data", ""))
                except Exception:
                    continue
                if msg.get("id") == rid:
                    chosen = msg
            body = chosen if chosen is not None else (json.loads(body[-1]["data"]) if body else None)
        return status, body, ctype


class StdioClient:
    def __init__(self, state_dir):
        self.proc = subprocess.Popen(
            [GUARD, "--name", "t", "--state-dir", state_dir, "--readonly", "read_ticket",
             "--approve", "deny", "--", sys.executable, STDIO_FAKE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.next_id = 0

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def recv(self):
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("stdio guard closed")
        return json.loads(line)

    def initialize(self):
        self.next_id += 1
        self.send({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "stdio-probe", "version": "0"},
            },
        })
        return self.recv()

    def initialized(self):
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": "tools/list"})
        return self.recv()

    def call(self, name, args=None):
        self.next_id += 1
        self.send({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args or {}},
        })
        return 200, self.recv(), "application/json"

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


def raw_post(port, body, headers):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("POST", "/mcp", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, (json.loads(data.decode("utf-8")) if data else None)
    finally:
        conn.close()


def origin_rule(body):
    return ((body or {}).get("error") or {}).get("data", {}).get("rule")


def outcome(body):
    if not isinstance(body, dict):
        return ("missing",)
    if "error" in body:
        err = body.get("error") or {}
        return ("error", err.get("code"), (err.get("data") or {}).get("rule"))
    return ("ok",)


def probe_sequence(client):
    results = []
    results.append(("clean-write", outcome(client.call("write_file", {"path": "clean.md"})[1])))
    results.append(("read", outcome(client.call("read_ticket", {"ticket_id": 7})[1])))
    results.append(("tainted-write", outcome(client.call("write_file", {"path": "tainted.md"})[1])))
    results.append(("unknown-tool", outcome(client.call("some_unmapped_tool", {})[1])))
    results.append(("egress", outcome(client.call("http_post", {"url": "https://audit.example/ingest", "body": "x"})[1])))
    results.append(("sensitive", outcome(client.call("write_file", {"path": ".env"})[1])))
    results.append(("read-after-taint", outcome(client.call("read_ticket", {"ticket_id": 7})[1])))
    return results


def read_state_text(root):
    chunks = []
    for dirpath, _, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    chunks.append(fh.read())
            except OSError:
                pass
    return "\n".join(chunks)


def test_origin_and_host():
    print("Origin and Host checks")
    with tempfile.TemporaryDirectory() as state_dir:
        fake = FakeHTTPMCP()
        proc = None
        try:
            proc, port = start_proxy(state_dir, f"http://127.0.0.1:{fake.port}/mcp")
            body = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "origin-probe", "version": "0"},
                },
            }, separators=(",", ":"))
            base = {"Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream"}

            status, resp = raw_post(port, body, {
                **base,
                "Host": f"evil.example:{port}",
                "Origin": f"http://evil.example:{port}",
            })
            check("Origin evil + Host evil returns 403", status == 403, f"status={status}")
            check("Origin evil + Host evil names ORIGIN_FORBIDDEN",
                  origin_rule(resp) == "ORIGIN_FORBIDDEN", str(resp)[:160])

            status, resp = raw_post(port, body, {
                **base,
                "Host": "evil.example",
            })
            check("no Origin + Host evil returns 403", status == 403, f"status={status}")
            check("no Origin + Host evil names ORIGIN_FORBIDDEN",
                  origin_rule(resp) == "ORIGIN_FORBIDDEN", str(resp)[:160])

            status, resp = raw_post(port, body, {
                **base,
                "Host": f"127.0.0.1:{port}",
                "Origin": f"http://localhost:{port}",
            })
            check("localhost Origin + 127.0.0.1 Host is allowed",
                  status == 200 and isinstance(resp, dict) and "result" in resp,
                  f"status={status} body={str(resp)[:160]}")
        finally:
            stop_process(proc)
            fake.close()


def test_parity_and_transport():
    print("HTTP proxy parity, sessions, auth pass-through, token non-persistence")
    with tempfile.TemporaryDirectory() as state_dir:
        fake = FakeHTTPMCP(require_auth=True)
        auth = "Bearer test-token"
        upstream = f"http://127.0.0.1:{fake.port}/mcp?url-secret=URL-TOKEN"
        proc = None
        try:
            proc, port = start_proxy(state_dir, upstream)
            client = HTTPClient(port, token=auth)
            status, body, _ = client.initialize()
            check("initialize returns 200", status == 200, f"status={status}")
            check("initialize result is present", isinstance(body, dict) and "result" in body, str(body)[:160])
            check("upstream session id reaches the client", bool(client.session), str(client.session))
            status, _, _ = client.initialized()
            check("initialized notification returns 202", status == 202, f"status={status}")
            status, body, _ = client.list_tools()
            check("tools/list returns 200", status == 200 and isinstance(body, dict), str(body)[:160])
            check("auth header reached upstream", fake.state.auth_headers and fake.state.auth_headers[-1] == auth,
                  str(fake.state.auth_headers[-1:]))

            http_results = probe_sequence(client)
            expected = [
                ("clean-write", ("ok",)),
                ("read", ("ok",)),
                ("tainted-write", ("error", -32000, "TAINT_SINK")),
                ("unknown-tool", ("error", -32000, "TAINT_SINK")),
                ("egress", ("error", -32000, "EGRESS_TARGET")),
                ("sensitive", ("error", -32000, "SENSITIVE_TARGET")),
                ("read-after-taint", ("ok",)),
            ]
            check("HTTP proxy blocks the expected calls", http_results == expected, str(http_results))
            status, _ = client.delete()
            check("DELETE terminates the upstream session", status == 204, f"status={status}")
        finally:
            stop_process(proc)
            fake.close()
        text = read_state_text(state_dir)
        check("auth token is not in state files", auth not in text)
        check("upstream URL query token is not in state files", "URL-TOKEN" not in text)

    with tempfile.TemporaryDirectory() as state_dir:
        stdio = StdioClient(state_dir)
        try:
            stdio.initialize()
            stdio.initialized()
            stdio.list_tools()
            stdio_results = probe_sequence(stdio)
        finally:
            stdio.close()
        check("stdio proxy produces the same blocks as HTTP", http_results == stdio_results,
              f"http={http_results} stdio={stdio_results}")


def test_sse_post_and_notification():
    print("POST SSE responses and server notifications")
    with tempfile.TemporaryDirectory() as state_dir:
        fake = FakeHTTPMCP()
        proc = None
        try:
            # Trust the two probe tools so their own results do not taint the
            # session; the SSE notification is then the only possible taint.
            proc, port = start_proxy(
                state_dir,
                f"http://127.0.0.1:{fake.port}/mcp",
                extra_flags=("--trust", "sse_echo,sse_notify"),
            )
            client = HTTPClient(port)
            client.initialize()
            client.initialized()
            client.list_tools()
            status, body, ctype = client.call("sse_echo", {})
            check("SSE response status is 200", status == 200, f"status={status}")
            check("SSE response content type is event-stream", ctype.startswith("text/event-stream"), ctype)
            check("SSE response is parsed", isinstance(body, dict) and body.get("result"), str(body)[:160])
            check("SSE response text arrived", "sse ok" in body["result"]["content"][0]["text"], str(body)[:160])

            status, body, ctype = client.call("sse_notify", {})
            check("SSE notification response is parsed", isinstance(body, dict) and body.get("result"), str(body)[:160])
            status, body, ctype = client.call("write_file", {"path": "after-notify.md"})
            check("content notification over SSE taints the session",
                  outcome(body) == ("error", -32000, "TAINT_SINK"), str(body)[:160])
        finally:
            stop_process(proc)
            fake.close()


def test_sse_get():
    print("GET SSE stream")
    with tempfile.TemporaryDirectory() as state_dir:
        fake = FakeHTTPMCP(enable_get_sse=True)
        proc = None
        try:
            proc, port = start_proxy(state_dir, f"http://127.0.0.1:{fake.port}/mcp")
            client = HTTPClient(port)
            client.initialize()
            client.initialized()
            client.list_tools()
            status, events = client.get_stream()
            payloads = [ev.get("data", "") for ev in events]
            check("GET SSE returns 200", status == 200, f"status={status}")
            check("GET SSE carries the server notification", any("HTTP-GET-INJECT-MARKER" in p for p in payloads),
                  str(payloads)[:200])
            time.sleep(0.1)
            status, body, _ = client.call("write_file", {"path": "after-get.md"})
            check("content notification over GET SSE taints the session",
                  outcome(body) == ("error", -32000, "TAINT_SINK"), str(body)[:160])
        finally:
            stop_process(proc)
            fake.close()


def test_pin_quarantine():
    print("pin persistence and quarantine over HTTP")
    with tempfile.TemporaryDirectory() as state_dir:
        fake1 = FakeHTTPMCP()
        proc1 = None
        try:
            proc1, port1 = start_proxy(state_dir, f"http://127.0.0.1:{fake1.port}/mcp")
            client1 = HTTPClient(port1)
            client1.initialize()
            client1.initialized()
            client1.list_tools()
            status, body, _ = client1.call("write_file", {"path": "first.md"})
            check("first definition is allowed", outcome(body) == ("ok",), str(body)[:160])
        finally:
            stop_process(proc1)
            fake1.close()

        fake2 = FakeHTTPMCP(desc_v2=True)
        proc2 = None
        try:
            proc2, port2 = start_proxy(state_dir, f"http://127.0.0.1:{fake2.port}/mcp")
            client2 = HTTPClient(port2)
            client2.initialize()
            client2.initialized()
            client2.list_tools()
            status, body, _ = client2.call("write_file", {"path": "second.md"})
            check("changed definition is quarantined",
                  outcome(body) == ("error", -32001, "MANIFEST_QUARANTINE"), str(body)[:160])
        finally:
            stop_process(proc2)
            fake2.close()


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    t0 = time.time()
    test_origin_and_host()
    test_parity_and_transport()
    test_sse_post_and_notification()
    test_sse_get()
    test_pin_quarantine()
    print(f"\n{passed} passed, {len(failed)} failed in {time.time() - t0:.1f}s")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
