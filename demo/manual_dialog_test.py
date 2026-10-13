"""Manual check of the approval dialog. Run it on a machine with a screen:

    python demo/manual_dialog_test.py

It starts the guard with --approve dialog in front of demo/fake_server.py, taints
the session, and asks for two clicks: Allow (Yes) once, then Deny (No) once.
Add --with-timeout to also leave a third dialog untouched for 60 seconds, which
must be denied automatically.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import selftest  # noqa: E402


def ask(s, label):
    s.send("tools/call", {"name": "write_file", "arguments": {"path": "secret-plan.txt"}})
    print(label, flush=True)
    return s.recv(timeout=150)


def main():
    results = []
    with tempfile.TemporaryDirectory() as d:
        s = selftest.Session(d, extra_flags=("--approve", "dialog"))
        s.start()
        s.call("read_ticket")  # taints the session, so the next write needs approval
        r = ask(s, "A dialog should appear now. Click YES (allow).")
        results.append(("Yes lets the call through", "result" in r))
        r = ask(s, "Another dialog should appear. Click NO (deny).")
        results.append(("No returns -32002 APPROVAL_DENIED", (r.get("error") or {}).get("code") == -32002))
        if "--with-timeout" in sys.argv:
            r = ask(s, "A third dialog should appear. Do NOT click anything; it is denied after 60 seconds.")
            results.append(("No answer for 60 s is denied", (r.get("error") or {}).get("code") == -32002))
        s.close()
        audit = open(os.path.join(d, "audit-t.jsonl")).read()
        results.append(("audit log records approvals without argument values", '"event":"approval"' in audit and "secret-plan" not in audit))
    for label, ok in results:
        print(("PASS  " if ok else "FAIL  ") + label)
    sys.exit(0 if all(ok for _, ok in results) else 1)


if __name__ == "__main__":
    main()
