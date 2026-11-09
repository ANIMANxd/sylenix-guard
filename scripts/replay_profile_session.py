"""Replay a recorded normal session through the guard and count approvals.

The fixture names the server package (so the built-in profile is selected
automatically), the active minutes, and the tool calls. The replay server
answers every call with a short success result; the guard still classifies the
call and applies the profile plus the policy's allow paths.

    python scripts/replay_profile_session.py
    python scripts/replay_profile_session.py --session demo/fixtures/normal_session.json
    python scripts/replay_profile_session.py --max-per-hour 10

A prompt is counted when the guard would have to ask a human: a TAINT_SINK
block under approval: deny, or an APPROVAL_DENIED under approval: dialog.
Hard blocks (EGRESS_TARGET/SENSITIVE_TARGET) are reported separately because
no approval can override them.
"""
import argparse
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.environ.get("SYLENIX_GUARD") or os.path.join(
    ROOT, "bin", "sylenix-guard.exe" if sys.platform == "win32" else "sylenix-guard")
PROFILE_SERVER = os.path.join(ROOT, "tests", "probes", "profile_server.py")


class Session:
    def __init__(self, cmd, cwd, env):
        self.p = subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=env)
        self.q = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self._id = 0

    def _read(self):
        for line in self.p.stdout:
            self.q.put(line)
        self.q.put(None)

    def send(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()
        return self._id

    def recv(self, timeout=10):
        line = self.q.get(timeout=timeout)
        if line is None:
            raise RuntimeError("guard closed stdout")
        return json.loads(line)

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", default=os.path.join(ROOT, "demo", "fixtures", "normal_session.json"))
    ap.add_argument("--max-per-hour", type=float, default=10.0)
    ap.add_argument("--json", action="store_true", help="print a JSON summary")
    args = ap.parse_args()

    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    with open(args.session, encoding="utf-8") as fh:
        fixture = json.load(fh)

    calls = fixture.get("calls", [])
    identifier = fixture.get("server", "")
    name = fixture.get("name", "replay")
    active_minutes = float(fixture.get("active_minutes", 60))
    if active_minutes <= 0:
        sys.exit("active_minutes must be positive")
    tools = sorted({call.get("tool", "") for call in calls if call.get("tool")})

    with tempfile.TemporaryDirectory(prefix="sylenix-replay-") as d:
        workspace = os.path.join(d, "workspace")
        state = os.path.join(d, "guard")
        os.makedirs(workspace)
        os.makedirs(state)
        policy = os.path.join(d, "policy.yaml")
        with open(policy, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"""version: 1
approval: deny
servers:
  {name}:
    tools:
      write_file:
        class: write
        allow_paths: ["."]
""")
        env = dict(os.environ)
        env["PROFILE_TOOLS"] = ",".join(tools)
        cmd = [GUARD, "--name", name, "--state-dir", state, "--policy", policy,
               "--", sys.executable, PROFILE_SERVER, identifier]
        s = Session(cmd, workspace, env)
        try:
            s.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "replay", "version": "0"}})
            s.recv()
            s.p.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
            s.p.stdin.flush()
            s.send("tools/list")
            s.recv()

            prompt_responses = 0
            hard_responses = 0
            errors = 0
            for call in calls:
                s.send("tools/call", {"name": call.get("tool", ""), "arguments": call.get("arguments", {})})
                resp = s.recv()
                got = rule(resp)
                if got == "TAINT_SINK" or got == "APPROVAL_DENIED":
                    prompt_responses += 1
                elif got in ("EGRESS_TARGET", "SENSITIVE_TARGET"):
                    hard_responses += 1
                elif "error" in resp:
                    errors += 1
            code = s.close()
        finally:
            if s.p.poll() is None:
                s.p.kill()

        audit_path = os.path.join(state, "audit-" + name + ".jsonl")
        prompts = prompt_responses
        hard_blocks = hard_responses
        profile = ""
        profile_source = ""
        if os.path.exists(audit_path):
            prompts = 0
            hard_blocks = 0
            with open(audit_path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("event") == "policy_loaded":
                        profile = rec.get("profile", "")
                        profile_source = rec.get("profile_source", "")
                    if rec.get("event") == "block":
                        if rec.get("rule") in ("TAINT_SINK", "APPROVAL_DENIED"):
                            prompts += 1
                        elif rec.get("rule") in ("EGRESS_TARGET", "SENSITIVE_TARGET"):
                            hard_blocks += 1

    hours = active_minutes / 60.0
    per_hour = prompts / hours
    summary = {
        "session": os.path.abspath(args.session),
        "profile": profile,
        "profile_source": profile_source,
        "calls": len(calls),
        "approval_prompts": prompts,
        "active_hours": round(hours, 3),
        "prompts_per_active_hour": round(per_hour, 3),
        "hard_blocks": hard_blocks,
        "errors": errors,
        "max_per_hour": args.max_per_hour,
        "within_budget": per_hour < args.max_per_hour,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"session: {summary['session']}")
        print(f"profile: {profile or 'none'} ({profile_source or 'no built-in profile'})")
        print(f"calls replayed: {len(calls)} over {hours:.2f} active hour(s)")
        print(f"approval prompts needed: {prompts} ({per_hour:.2f}/hour)")
        print(f"hard blocks: {hard_blocks}; errors: {errors}")
        print(f"budget: < {args.max_per_hour:g}/hour -> {'PASS' if summary['within_budget'] else 'FAIL'}")
    if not summary["within_budget"] or errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
