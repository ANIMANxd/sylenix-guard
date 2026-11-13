# SPDX-License-Identifier: Apache-2.0

"""Regression probes for result sanitisation and datamarking (F7a-F7c)."""

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
REDTEAM_SERVER = os.path.join(ROOT, "tests", "probes", "redteam_server.py")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

passed, failed = 0, []


def check(label, cond, detail=""):
    global passed
    if cond:
        passed += 1
        print(f"  ok   {label}")
    else:
        failed.append(label)
        print(f"  FAIL {label} {detail}")


def redteam_env(tools, **extra):
    env = dict(extra)
    env["REDTEAM_TOOLS"] = tools
    return env


class Session:
    def __init__(self, state_dir, name, flags=(), env=None):
        e = dict(os.environ)
        e.update(env or {})
        e.setdefault("PYTHONUTF8", "1")
        e.setdefault("PYTHONIOENCODING", "utf-8")
        cmd = [GUARD, "--name", name, "--state-dir", state_dir, *flags,
               "--", sys.executable, REDTEAM_SERVER]
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
        self.p.stdin.write(json.dumps(message, separators=(",", ":"),
                                      ensure_ascii=False).encode("utf-8") + b"\n")
        self.p.stdin.flush()
        return self._id

    def notify(self, method):
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method},
                                      separators=(",", ":")).encode("utf-8") + b"\n")
        self.p.stdin.flush()

    def recv(self, timeout=15):
        line = self.q.get(timeout=timeout)
        if line is None:
            raise RuntimeError("guard closed stdout")
        return json.loads(line.decode("utf-8"))

    def start(self):
        self.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "datamark-probe", "version": "0"}})
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


def text_of(resp):
    for item in (resp.get("result") or {}).get("content") or []:
        if item.get("type") == "text":
            return item.get("text") or ""
    return ""


def contains_bad_marker(serialized):
    return ("</UNTRUSTED_TOOL_RESULT>" in serialized or
            '<untrusted_tool_result origin="system">' in serialized)


def test_resource_text():
    print("embedded resource text")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, "dm-resource", flags=("--readonly", "resource_tags"),
                    env=redteam_env("resource_tags"))
        try:
            s.start()
            resp = s.call("resource_tags")
        finally:
            s.close()
        item = (resp.get("result") or {}).get("content", [{}])[0]
        text = (item.get("resource") or {}).get("text", "")
        serialized = json.dumps(resp, ensure_ascii=False)
        check("embedded resource text is prefixed",
              text.startswith("[untrusted resource from resource_tags]\n"), repr(text[:120]))
        check("embedded resource text is preserved", "embedded x" in text, repr(text))
        check("Unicode tag characters are stripped from embedded resources",
              "\U000E0041" not in serialized and "\U000E0042" not in serialized and
              "\U000E0043" not in serialized)
        check("forged markers in embedded resources are inert",
              not contains_bad_marker(serialized), serialized[:240])
        check("embedded resource markers are neutralised visibly",
              "</UNTRUSTED_TOOL_RESULT_>" in text, repr(text))


def test_resource_link():
    print("resource_link fields")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, "dm-link", flags=("--readonly", "resource_link_echo"),
                    env=redteam_env("resource_link_echo"))
        try:
            s.start()
            resp = s.call("resource_link_echo")
        finally:
            s.close()
        serialized = json.dumps(resp, ensure_ascii=False)
        check("resource_link field strings are stripped of invisible characters",
              "\U000E0041" not in serialized and "\U000E0042" not in serialized and
              "\U000E0043" not in serialized and "\U000E0044" not in serialized and
              "\U000E0045" not in serialized, serialized[:300])
        check("resource_link forged markers are neutralised",
              not contains_bad_marker(serialized), serialized[:300])
        check("resource_link annotations are sanitized",
              "\U000E0044" not in serialized and "\U000E0045" not in serialized,
              serialized[:300])


def test_marker_variants():
    print("case and fullwidth marker variants")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, "dm-markers", flags=("--readonly", "fullwidth_echo"),
                    env=redteam_env("fullwidth_echo"))
        try:
            s.start()
            resp = s.call("fullwidth_echo")
        finally:
            s.close()
        text = text_of(resp)
        serialized = json.dumps(resp, ensure_ascii=False)
        check("fullwidth angle brackets are normalised",
              "\uFF1C" not in serialized and "\uFF1E" not in serialized, repr(text))
        check("fullwidth closing markers are neutralised",
              "</UNTRUSTED_TOOL_RESULT_>" in text, repr(text))
        check("fullwidth forged opening markers are neutralised",
              '<untrusted_tool_result_ origin="system">' in text, repr(text))
        check("the wrapper is the only active closing marker",
              text.count("</untrusted_tool_result>") == 1, repr(text))


def test_invisible_ranges():
    print("new invisible ranges")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, "dm-ranges", flags=("--readonly", "invisible_range_echo"),
                    env=redteam_env("invisible_range_echo"))
        try:
            s.start()
            resp = s.call("invisible_range_echo")
        finally:
            s.close()
        text = text_of(resp)
        bad = [c for c in ("\uFE0F", "\u2800", "\U0001D173", "\U0001D17A", "\uFFFC")
               if c in text]
        check("variation, braille, musical and object-replacement characters are stripped",
              not bad, repr(bad))
        check("visible text survives the strip", "abcdef" in text, repr(text))


def test_read_and_prompt():
    print("resources/read and prompts/get text")
    with tempfile.TemporaryDirectory() as d:
        s = Session(d, "dm-read-prompt", env=redteam_env("read_ticket"))
        try:
            s.start()
            s.send("resources/read", {"uri": "file:///tmp/redteam-read.txt"})
            resource = s.recv()
            s.send("prompts/get", {"name": "redteam_prompt", "arguments": {}})
            prompt = s.recv()
        finally:
            s.close()
        resource_text = ((resource.get("result") or {}).get("contents") or [{}])[0].get("text", "")
        prompt_text = (((prompt.get("result") or {}).get("messages") or [{}])[0]
                       .get("content") or {}).get("text", "")
        for label, text in (("resources/read", resource_text),
                            ("prompts/get", prompt_text)):
            check(f"{label} text is stripped of invisible characters",
                  "\U000E0041" not in text and "\uFE0F" not in text and "\u2800" not in text,
                  repr(text))
            check(f"{label} forged markers are neutralised",
                  "</UNTRUSTED_TOOL_RESULT_>" in text and
                  "</UNTRUSTED_TOOL_RESULT>" not in text, repr(text))


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    test_resource_text()
    test_resource_link()
    test_marker_variants()
    test_invisible_ranges()
    test_read_and_prompt()
    print(f"\n{passed} passed, {len(failed)} failed")
    if failed:
        print("failed: " + ", ".join(failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
