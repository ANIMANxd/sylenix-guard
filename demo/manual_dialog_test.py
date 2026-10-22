"""Manual check of the approval dialog. Run it on a machine with a screen:

    python demo/manual_dialog_test.py

It starts the guard with --approve dialog in front of demo/fake_server.py, taints
the session, and asks for four clicks: Allow Once, then Allow Tool for 15m, then
(no dialog should appear: the grant covers the call), then Deny. Add
--with-timeout to also leave one dialog untouched for 60 seconds, which must be
denied automatically.
"""
import os
import sys
import tempfile
import time

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
        r = ask(s, "A dialog should appear now. Click ALLOW ONCE.")
        results.append(("Allow Once lets one call through", "result" in r))
        r = ask(s, "Another dialog should appear. Click ALLOW TOOL FOR 15M.")
        results.append(("Allow Tool for 15m lets the call through", "result" in r))
        t0 = time.time()
        s.send("tools/call", {"name": "write_file", "arguments": {"path": "secret-plan.txt"}})
        print("No dialog should appear now: the 15m grant covers this call.", flush=True)
        try:
            r = s.recv(timeout=8)
            fast = time.time() - t0 < 8
        except Exception:
            r, fast = {}, False
        results.append(("no prompt while the grant is live", "result" in r and fast))
        r = ask(s, "Another dialog should appear. Click DENY.")
        results.append(("Deny returns -32002 APPROVAL_DENIED", (r.get("error") or {}).get("code") == -32002))
        if "--with-timeout" in sys.argv:
            r = ask(s, "A last dialog should appear. Do NOT click anything; it is denied after 60 seconds.")
            results.append(("No answer for 60 s is denied", (r.get("error") or {}).get("code") == -32002))
        s.close()
        audit = open(os.path.join(d, "audit-t.jsonl")).read()
        results.append(("audit log records the grant", '"decision":"grant"' in audit and '"event":"grant_recorded"' in audit))
        results.append(("audit log records approvals without argument values", '"event":"approval"' in audit and "secret-plan" not in audit))
    for label, ok in results:
        print(("PASS  " if ok else "FAIL  ") + label)
    sys.exit(0 if all(ok for _, ok in results) else 1)


if __name__ == "__main__":
    main()
