"""Probes for `sylenix-guard stats`.

The exact fixture check keeps the Go summary identical to
`scripts/summarize_audit.py`. The live-log checks cover prompts per active hour,
the short-session n/a case, usage errors and clear-taint events.

Run after building the guard:

    python3 tests/probes/test_stats.py
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GUARD = os.environ.get("SYLENIX_GUARD") or os.path.join(
    ROOT, "bin", "sylenix-guard.exe" if sys.platform == "win32" else "sylenix-guard")

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


def write_log(path, rows):
    write(path, "".join(json.dumps(row) + "\n" for row in rows))


def run(args, cwd=ROOT, timeout=30):
    return subprocess.run([GUARD, *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)


def normalized(text):
    return text.replace("\r\n", "\n")


def case_fixture():
    print("stats matches the audit fixture")
    p = run(["stats", "--file", "demo/fixtures/audit_sample.jsonl"])
    expected_path = os.path.join(ROOT, "demo", "fixtures", "audit_sample.expected.txt")
    expected = open(expected_path, encoding="utf-8", newline="").read()
    check("fixture: exit 0", p.returncode == 0, p.stderr)
    check("fixture: output matches the summarizer fixture",
          normalized(p.stdout) == normalized(expected),
          normalized(p.stdout))


def case_named_log():
    print("stats --name reads the guard audit log")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        rows = [
            {"ts": "2026-11-09T10:00:00Z", "server": "t", "event": "start"},
            {"ts": "2026-11-09T10:02:00Z", "server": "t", "event": "taint_latched", "origin": "read"},
            {"ts": "2026-11-09T10:04:00Z", "server": "t", "event": "approval", "tool": "write", "granted": True},
            {"ts": "2026-11-09T10:06:00Z", "server": "t", "event": "approval", "tool": "write", "granted": False},
            {"ts": "2026-11-09T10:10:00Z", "server": "t", "event": "exit", "code": 0},
        ]
        write_log(os.path.join(state, "audit-t.jsonl"), rows)
        p = run(["stats", "--name", "t", "--state-dir", state])
        out = normalized(p.stdout)
        check("named: exit 0", p.returncode == 0, p.stderr)
        check("named: reads the expected file", f"file: {os.path.join(state, 'audit-t.jsonl')}" in out, out)
        check("named: one tainted session", "sessions: 1  (tainted: 1)" in out, out)
        check("named: prompts per active hour is 12.0", "approval prompts per active hour: 12.0" in out, out)
        check("named: approval counts", "approvals granted: 1   approvals denied: 1" in out, out)
        check("named: approval by tool", "  write granted=1 denied=1" in out, out)
        check("named: no blocks", "blocks by tool/rule:\n  none" in out, out)


def case_short_active():
    print("stats reports n/a below the minimum active time")
    with tempfile.TemporaryDirectory() as base:
        path = os.path.join(base, "short.jsonl")
        write_log(path, [
            {"ts": "2026-11-09T10:00:00Z", "server": "t", "event": "start"},
            {"ts": "2026-11-09T10:01:00Z", "server": "t", "event": "approval", "tool": "write", "granted": True},
            {"ts": "2026-11-09T10:02:00Z", "server": "t", "event": "exit", "code": 0},
        ])
        p = run(["stats", "--file", path])
        out = normalized(p.stdout)
        check("short: exit 0", p.returncode == 0, p.stderr)
        check("short: prompts per hour is n/a", "approval prompts per active hour: n/a (active time under 300 s)" in out, out)


def case_clear_events():
    print("stats does not count clear-taint dialogs as approval prompts")
    with tempfile.TemporaryDirectory() as base:
        path = os.path.join(base, "clear.jsonl")
        write_log(path, [
            {"ts": "2026-11-09T10:00:00Z", "server": "t", "event": "start"},
            {"ts": "2026-11-09T10:01:00Z", "server": "t", "event": "taint_latched", "origin": "read"},
            {"ts": "2026-11-09T10:02:00Z", "server": "t", "event": "approval", "tool": "write", "granted": True},
            {"ts": "2026-11-09T10:03:00Z", "server": "t", "event": "CLEAR_TAINT", "who": "me", "granted": True},
            {"ts": "2026-11-09T10:04:00Z", "server": "t", "event": "CLEAR_TAINT_DENIED", "who": "me", "granted": False},
            {"ts": "2026-11-09T10:05:00Z", "server": "t", "event": "exit", "code": 0},
        ])
        p = run(["stats", "--file", path])
        out = normalized(p.stdout)
        check("clear events: exit 0", p.returncode == 0, p.stderr)
        check("clear events: events counted", "events: 6" in out, out)
        check("clear events: only approval prompts count", "approvals granted: 1   approvals denied: 0" in out, out)
        check("clear events: prompts per active hour is 12.0", "approval prompts per active hour: 12.0" in out, out)


def case_usage():
    print("stats usage errors")
    with tempfile.TemporaryDirectory() as base:
        state = os.path.join(base, "state")
        os.makedirs(state)
        empty = os.path.join(base, "empty.jsonl")
        write(empty, "")
        invalid = os.path.join(base, "invalid.jsonl")
        write(invalid, "{not json\n")
        missing = os.path.join(base, "missing.jsonl")

        p = run(["stats"])
        check("usage: no selector exits 2", p.returncode == 2, p.stderr)
        p = run(["stats", "--name", "t", "--file", "x"])
        check("usage: both selectors exit 2", p.returncode == 2, p.stderr)
        p = run(["stats", "--file", missing])
        check("usage: missing file exits 2", p.returncode == 2, p.stderr)
        p = run(["stats", "--file", empty])
        check("usage: empty log exits 2", p.returncode == 2, p.stderr)
        p = run(["stats", "--file", invalid])
        check("usage: invalid JSON exits 2", p.returncode == 2, p.stderr)
        p = run(["stats", "--name", "t", "--state-dir", state, "--file", "x"])
        check("usage: --state-dir with --file exits 2", p.returncode == 2, p.stderr)


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    case_fixture()
    case_named_log()
    case_short_active()
    case_clear_events()
    case_usage()
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
