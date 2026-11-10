# SPDX-License-Identifier: Apache-2.0

"""Regression probes for `sylenix-guard doctor`.

Covers a clean setup and one case for every doctor finding:
  - clean wrapped + allowlisted + dialog setup
  - unwrapped stdio server
  - remote server
  - missing allowlist entry
  - allowlist enforcement off
  - allowlist SHA-256 mismatch
  - --allow-write-under at home / repo root (and a safe subdirectory)
  - --trust on an egress-capable server
  - approvals off
  - unreadable pin file
  - unsigned policy/pins with --require-signatures
  - outdated Guard wrapper metadata and an older Guard binary
  - missing Guard binary, malformed wrapper, broken config, malformed server
  - JSON shape, no argument/env leakage, and doctor is read-only

Run after building the guard:

    python3 tests/probes/test_doctor.py
"""
import json
import os
import shutil
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


def write_json(path, obj):
    write(path, json.dumps(obj, indent=2) + "\n")


def setup_tree(base):
    home = os.path.join(base, "home")
    appdata = os.path.join(base, "appdata")
    xdg = os.path.join(base, "xdg")
    project = os.path.join(base, "project")
    state = os.path.join(base, "state")
    for path in (home, appdata, xdg, project, state):
        os.makedirs(path, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "HOME": home,
        "USERPROFILE": home,
        "APPDATA": appdata,
        "XDG_CONFIG_HOME": xdg,
    })
    return home, project, state, env


def setup_server(base):
    home, project, state, env = setup_tree(base)
    server_py = os.path.join(project, "server.py")
    write(server_py, "# test server\n")
    policy = os.path.join(base, "policy.yaml")
    return home, project, state, env, server_py, policy


def run(args, env, cwd, input_text=None, timeout=60):
    return subprocess.run([GUARD, *args], env=env, cwd=cwd, input=input_text,
                          capture_output=True, text=True, timeout=timeout)


def doctor_json(env, cwd, *args):
    p = run(["doctor", "--json", *args], env, cwd)
    try:
        data = json.loads(p.stdout) if p.stdout.strip() else None
    except json.JSONDecodeError:
        data = None
    return p, data


def codes(data):
    if not data:
        return set()
    return {f.get("code") for f in data.get("findings", [])}


def finding(data, code):
    if not data:
        return None
    for item in data.get("findings", []):
        if item.get("code") == code:
            return item
    return None


def first_server(data):
    if not data:
        return {}
    configs = data.get("configs", [])
    if not configs or not configs[0].get("servers"):
        return {}
    return configs[0]["servers"][0]


def config_path(home):
    return os.path.join(home, ".claude.json")


def write_config(home, servers):
    write_json(config_path(home), {"mcpServers": servers})


def wrapper(policy, state, original_cmd, original_args, extra_flags=None, guard=None, meta_version=1):
    args = [f"--policy={policy}", f"--state-dir={state}"]
    if extra_flags:
        args.extend(extra_flags)
    args += ["--", original_cmd, *original_args]
    entry = {"command": guard or GUARD, "args": args}
    if meta_version is not None:
        entry["_sylenixGuard"] = {
            "version": meta_version,
            "hadArgs": bool(original_args),
            "hadEnv": False,
        }
    return entry


def write_policy(path, approval="dialog", enforced=True, allowlist=None, extra=""):
    lines = ["version: 1", f"approval: {approval}"]
    if enforced is not None:
        lines.append(f"allowlist_enforced: {'true' if enforced else 'false'}")
    if allowlist:
        lines.append("allowlist:")
        for name, command, args, sha in allowlist:
            lines.append(f"  - name: {json.dumps(name)}")
            lines.append(f"    command: {json.dumps(command)}")
            if args:
                lines.append("    args:")
                for arg in args:
                    lines.append(f"      - {json.dumps(arg)}")
            else:
                lines.append("    args: []")
            if sha:
                lines.append(f"    sha256: {json.dumps(sha)}")
    if extra:
        lines.append(extra.rstrip("\n"))
    write(path, "\n".join(lines) + "\n")


def basic_policy(policy, server_py, **kwargs):
    write_policy(policy, allowlist=[("demo", sys.executable, [server_py], None)], **kwargs)


def case_clean():
    print("clean setup")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        write_config(home, {"demo": wrapper(policy, state, sys.executable, [server_py])})

        p, data = doctor_json(env, project)
        check("clean: exit 0", p.returncode == 0, p.stderr)
        check("clean: valid JSON", data is not None, p.stdout)
        check("clean: clean is true", bool(data) and data.get("clean") is True)
        check("clean: no findings", bool(data) and data.get("findings") == [])
        check("clean: one config", bool(data) and len(data.get("configs", [])) == 1)
        server = first_server(data)
        check("clean: server wrapped", server.get("wrapped") is True)
        check("clean: server allowlisted", server.get("allowlisted") is True)
        check("clean: approval dialog", server.get("approval") == "dialog")
        check("clean: no args/env in JSON", "args" not in server and "env" not in server)
        check("clean: version present", bool(data) and bool(data.get("version")))

        human = run(["doctor"], env, project)
        check("clean: human exit 0", human.returncode == 0, human.stderr)
        check("clean: human says no findings", "No findings" in human.stdout, human.stdout)
        check("clean: human shows wrapped", "wrapped by Guard" in human.stdout, human.stdout)
        check("clean: human shows allowlisted", "allowlisted" in human.stdout, human.stdout)


def case_not_wrapped():
    print("unwrapped stdio server")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        write_policy(policy, allowlist=[("plain", sys.executable, [server_py], None)])
        write_config(home, {"plain": {"command": sys.executable, "args": [server_py]}})

        p, data = doctor_json(env, project, "--policy", policy)
        check("unwrapped: exit 1", p.returncode == 1, p.stderr)
        check("unwrapped: NOT_WRAPPED", "NOT_WRAPPED" in codes(data), p.stdout)
        check("unwrapped: server not wrapped", first_server(data).get("wrapped") is False)
        check("unwrapped: server allowlisted", first_server(data).get("allowlisted") is True)


def case_remote():
    print("remote server is not covered")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        write_policy(policy, enforced=None)
        secret = "SECRET-URL-TOKEN"
        write_config(home, {"remote": {"type": "http", "url": f"https://user:{secret}@example.invalid/mcp"}})

        p, data = doctor_json(env, project, "--policy", policy)
        check("remote: exit 1", p.returncode == 1, p.stderr)
        check("remote: REMOTE_NOT_COVERED", "REMOTE_NOT_COVERED" in codes(data), p.stdout)
        check("remote: transport remote", first_server(data).get("transport") == "remote")
        check("remote: URL is not printed", secret not in p.stdout, p.stdout)


def case_not_allowlisted():
    print("server not on the allowlist")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        write_policy(policy, allowlist=[("other", "definitely-not-this-command", [], None)])
        write_config(home, {"demo": wrapper(policy, state, sys.executable, [server_py])})

        p, data = doctor_json(env, project)
        check("allowlist: exit 1", p.returncode == 1, p.stderr)
        check("allowlist: NOT_ALLOWLISTED", "NOT_ALLOWLISTED" in codes(data), p.stdout)
        check("allowlist: not allowlisted", first_server(data).get("allowlisted") is False)
        check("allowlist: enforcement is on", "ALLOWLIST_NOT_ENFORCED" not in codes(data), p.stdout)


def case_allowlist_not_enforced():
    print("allowlist enforcement is off")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py, enforced=False)
        write_config(home, {"demo": wrapper(policy, state, sys.executable, [server_py])})

        p, data = doctor_json(env, project)
        check("enforcement: exit 1", p.returncode == 1, p.stderr)
        check("enforcement: ALLOWLIST_NOT_ENFORCED", "ALLOWLIST_NOT_ENFORCED" in codes(data), p.stdout)
        check("enforcement: allowlisted", first_server(data).get("allowlisted") is True)
        check("enforcement: no NOT_ALLOWLISTED", "NOT_ALLOWLISTED" not in codes(data), p.stdout)


def case_hash_mismatch():
    print("allowlist SHA-256 mismatch")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        write_policy(policy, allowlist=[("demo", sys.executable, [server_py], "0" * 64)])
        write_config(home, {"demo": wrapper(policy, state, sys.executable, [server_py])})

        p, data = doctor_json(env, project)
        check("hash: exit 1", p.returncode == 1, p.stderr)
        check("hash: ALLOWLIST_HASH_MISMATCH", "ALLOWLIST_HASH_MISMATCH" in codes(data), p.stdout)
        check("hash: allowlisted", first_server(data).get("allowlisted") is True)
        check("hash: no NOT_ALLOWLISTED", "NOT_ALLOWLISTED" not in codes(data), p.stdout)


def case_risky_scratch_home():
    print("scratch root at home")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        entry = wrapper(policy, state, sys.executable, [server_py],
                        extra_flags=["--allow-write-under=" + home])
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        f = finding(data, "RISKY_SCRATCH")
        check("scratch home: exit 1", p.returncode == 1, p.stderr)
        check("scratch home: RISKY_SCRATCH", f is not None, p.stdout)
        check("scratch home: names home", bool(f) and "home" in f.get("detail", "").lower(), str(f))
        check("scratch home: has one fix", bool(f) and bool(f.get("fix")))


def case_risky_scratch_repo():
    print("scratch root at the repository root")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        os.makedirs(os.path.join(project, ".git"))
        basic_policy(policy, server_py)
        entry = wrapper(policy, state, sys.executable, [server_py],
                        extra_flags=["--allow-write-under", project])
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        f = finding(data, "RISKY_SCRATCH")
        check("scratch repo: exit 1", p.returncode == 1, p.stderr)
        check("scratch repo: RISKY_SCRATCH", f is not None, p.stdout)
        check("scratch repo: names repository", bool(f) and "repository" in f.get("detail", "").lower(), str(f))


def case_safe_scratch():
    print("scratch root under the project is not risky")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        os.makedirs(os.path.join(project, ".git"))
        out = os.path.join(project, "out")
        os.makedirs(out)
        basic_policy(policy, server_py)
        entry = wrapper(policy, state, sys.executable, [server_py],
                        extra_flags=["--allow-write-under", out])
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        check("safe scratch: exit 0", p.returncode == 0, p.stderr)
        check("safe scratch: no RISKY_SCRATCH", "RISKY_SCRATCH" not in codes(data), p.stdout)
        check("safe scratch: clean", bool(data) and data.get("clean") is True)


def case_trust_on_egress():
    print("--trust on an egress-capable server")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        write_policy(policy, allowlist=[("fetchdemo", "uvx", ["mcp-server-fetch"], None)])
        entry = wrapper(policy, state, "uvx", ["mcp-server-fetch"], extra_flags=["--trust", "fetch"])
        write_config(home, {"fetchdemo": entry})

        p, data = doctor_json(env, project)
        f = finding(data, "TRUST_ON_EGRESS")
        check("trust: exit 1", p.returncode == 1, p.stderr)
        check("trust: TRUST_ON_EGRESS", f is not None, p.stdout)
        check("trust: names the trusted tool", bool(f) and "fetch" in f.get("detail", ""), str(f))


def case_trust_safe():
    print("--trust on a server without egress tools is not flagged")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        entry = wrapper(policy, state, sys.executable, [server_py],
                        extra_flags=["--trust", "read_file"])
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        check("trust safe: exit 0", p.returncode == 0, p.stderr)
        check("trust safe: no TRUST_ON_EGRESS", "TRUST_ON_EGRESS" not in codes(data), p.stdout)


def case_approvals_off():
    print("approvals off")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py, approval="deny")
        write_config(home, {"demo": wrapper(policy, state, sys.executable, [server_py])})

        p, data = doctor_json(env, project)
        check("approvals: exit 1", p.returncode == 1, p.stderr)
        check("approvals: APPROVALS_OFF", "APPROVALS_OFF" in codes(data), p.stdout)
        check("approvals: approval deny", first_server(data).get("approval") == "deny")

        entry = wrapper(policy, state, sys.executable, [server_py],
                        extra_flags=["--approve", "dialog"])
        write_config(home, {"demo": entry})
        p2, data2 = doctor_json(env, project)
        check("approvals: wrapper dialog overrides policy", p2.returncode == 0, p2.stderr)
        check("approvals: no APPROVALS_OFF after override", "APPROVALS_OFF" not in codes(data2), p2.stdout)


def case_pins_unreadable():
    print("unreadable pin file")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        pins = os.path.join(state, f"pins-{os.path.basename(sys.executable)}.json")
        write(pins, "{not json\n")
        write_config(home, {"demo": wrapper(policy, state, sys.executable, [server_py])})

        p, data = doctor_json(env, project)
        check("pins: exit 1", p.returncode == 1, p.stderr)
        check("pins: PINS_UNREADABLE", "PINS_UNREADABLE" in codes(data), p.stdout)

        entry = wrapper(policy, state, sys.executable, [server_py], extra_flags=["--reset-pins"])
        write_config(home, {"demo": entry})
        p2, data2 = doctor_json(env, project)
        check("pins: --reset-pins suppresses the finding", p2.returncode == 0, p2.stderr)
        check("pins: no PINS_UNREADABLE with reset", "PINS_UNREADABLE" not in codes(data2), p2.stdout)


def case_unsigned():
    print("unsigned policy and pins with --require-signatures")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        pins = os.path.join(state, f"pins-{os.path.basename(sys.executable)}.json")
        write_json(pins, {"read_file": "a" * 64})
        write_config(home, {"demo": wrapper(policy, state, sys.executable, [server_py])})

        p, data = doctor_json(env, project, "--require-signatures")
        check("unsigned: exit 1", p.returncode == 1, p.stderr)
        check("unsigned: UNSIGNED_POLICY", "UNSIGNED_POLICY" in codes(data), p.stdout)
        check("unsigned: UNSIGNED_PINS", "UNSIGNED_PINS" in codes(data), p.stdout)

        p2, data2 = doctor_json(env, project)
        check("unsigned: clean without the flag", p2.returncode == 0, p2.stderr)
        check("unsigned: no unsigned findings without the flag",
              not {"UNSIGNED_POLICY", "UNSIGNED_PINS"} & codes(data2), p2.stdout)


def case_outdated_metadata():
    print("outdated Guard wrapper metadata")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        entry = wrapper(policy, state, sys.executable, [server_py], meta_version=0)
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        f = finding(data, "OUTDATED_GUARD")
        check("metadata: exit 1", p.returncode == 1, p.stderr)
        check("metadata: OUTDATED_GUARD", f is not None, p.stdout)
        check("metadata: detail mentions metadata", bool(f) and "metadata" in f.get("detail", "").lower(), str(f))


def build_old_guard(dest):
    exe = dest + (".exe" if sys.platform == "win32" else "")
    subprocess.run(["go", "build", "-ldflags", "-X main.version=0.0.0", "-o", exe,
                    "./cmd/sylenix-guard"],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    return exe


def case_outdated_binary():
    print("outdated Guard binary")
    if shutil.which("go") is None:
        check("old binary: go is available", False, "go not found")
        return
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        try:
            old = build_old_guard(os.path.join(base, "old-guard"))
        except subprocess.CalledProcessError as exc:
            check("old binary: build", False, (exc.stderr or "")[-400:])
            return
        basic_policy(policy, server_py)
        entry = wrapper(policy, state, sys.executable, [server_py], guard=old)
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        f = finding(data, "OUTDATED_GUARD")
        check("old binary: exit 1", p.returncode == 1, p.stderr)
        check("old binary: OUTDATED_GUARD", f is not None, p.stdout)
        check("old binary: detail mentions 0.0.0", bool(f) and "0.0.0" in f.get("detail", ""), str(f))


def case_guard_not_found():
    print("Guard binary is missing")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        missing = os.path.join(base, "missing-guard" + (".exe" if sys.platform == "win32" else ""))
        entry = wrapper(policy, state, sys.executable, [server_py], guard=missing)
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        check("missing guard: exit 1", p.returncode == 1, p.stderr)
        check("missing guard: GUARD_NOT_FOUND", "GUARD_NOT_FOUND" in codes(data), p.stdout)


def case_guard_version_unknown():
    print("Guard binary version cannot be read")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        not_guard = os.path.join(base, "not-a-guard-binary")
        write(not_guard, "this is not a Go binary\n")
        entry = wrapper(policy, state, sys.executable, [server_py], guard=not_guard)
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        check("version unknown: exit 1", p.returncode == 1, p.stderr)
        check("version unknown: GUARD_VERSION_UNKNOWN", "GUARD_VERSION_UNKNOWN" in codes(data), p.stdout)


def case_policy_invalid():
    print("invalid policy")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        write(policy, "version: 2\napproval: dialog\n")
        entry = wrapper(policy, state, sys.executable, [server_py])
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        check("policy invalid: exit 1", p.returncode == 1, p.stderr)
        check("policy invalid: POLICY_INVALID", "POLICY_INVALID" in codes(data), p.stdout)


def case_wrapper_invalid():
    print("malformed Guard wrapper")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        entry = {
            "command": GUARD,
            "args": [f"--policy={policy}"],
            "_sylenixGuard": {"version": 1, "hadArgs": True, "hadEnv": False},
        }
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        check("wrapper: exit 1", p.returncode == 1, p.stderr)
        check("wrapper: WRAPPER_INVALID", "WRAPPER_INVALID" in codes(data), p.stdout)


def case_broken_config():
    print("broken config")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        write(config_path(home), "{broken json\n")

        p, data = doctor_json(env, project)
        check("broken config: exit 1", p.returncode == 1, p.stderr)
        check("broken config: CONFIG_UNREADABLE", "CONFIG_UNREADABLE" in codes(data), p.stdout)
        check("broken config: JSON output is still valid", data is not None, p.stdout)


def case_server_invalid():
    print("malformed server entry")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        write_config(home, {"bad": {"command": 123}})

        p, data = doctor_json(env, project)
        check("server invalid: exit 1", p.returncode == 1, p.stderr)
        check("server invalid: SERVER_INVALID", "SERVER_INVALID" in codes(data), p.stdout)


def case_no_leak():
    print("doctor output never contains argument or env values")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        secret_arg = "SECRET-ARG-VALUE"
        secret_env = "SECRET-ENV-VALUE"
        write_policy(policy, allowlist=[
            ("demo", sys.executable, [server_py, "--api-key", secret_arg], None),
        ])
        entry = wrapper(policy, state, sys.executable, [server_py, "--api-key", secret_arg],
                        extra_flags=["--allow-write-under=" + home])
        entry["env"] = {"API_TOKEN": secret_env}
        write_config(home, {"demo": entry})

        p, data = doctor_json(env, project)
        check("no leak: secret arg absent from JSON", secret_arg not in p.stdout, p.stdout)
        check("no leak: secret env absent from JSON", secret_env not in p.stdout, p.stdout)
        server = first_server(data)
        check("no leak: no args/env fields in JSON", "args" not in server and "env" not in server, str(server))
        human = run(["doctor"], env, project)
        check("no leak: secret arg absent from human output", secret_arg not in human.stdout, human.stdout)
        check("no leak: secret env absent from human output", secret_env not in human.stdout, human.stdout)


def case_read_only():
    print("doctor does not modify configs, policy or pins")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        basic_policy(policy, server_py)
        pins = os.path.join(state, f"pins-{os.path.basename(sys.executable)}.json")
        write_json(pins, {"read_file": "a" * 64})
        write_config(home, {"demo": wrapper(policy, state, sys.executable, [server_py])})

        paths = (config_path(home), policy, pins)
        before = {path: open(path, "rb").read() for path in paths}
        before_listing = sorted(os.listdir(state))
        p, data = doctor_json(env, project, "--require-signatures")
        check("read-only: findings still reported", p.returncode == 1 and data is not None, p.stderr)
        check("read-only: config unchanged", open(config_path(home), "rb").read() == before[config_path(home)])
        check("read-only: policy unchanged", open(policy, "rb").read() == before[policy])
        check("read-only: pins unchanged", open(pins, "rb").read() == before[pins])
        check("read-only: no audit log created", not any(name.startswith("audit-") for name in os.listdir(state)))
        check("read-only: state listing unchanged", sorted(os.listdir(state)) == before_listing)


def case_usage():
    print("usage errors")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env, server_py, policy = setup_server(base)
        p = run(["doctor", "--json", "unexpected"], env, project)
        check("usage: unexpected argument exits 2", p.returncode == 2, p.stderr)
        p2 = run(["doctor", "--policy="], env, project)
        check("usage: empty policy exits 2", p2.returncode == 2, p2.stderr)


def case_no_configs():
    print("no supported configs found")
    with tempfile.TemporaryDirectory() as base:
        home, project, state, env = setup_tree(base)
        p, data = doctor_json(env, project)
        check("no configs: exit 0", p.returncode == 0, p.stderr)
        check("no configs: clean true", bool(data) and data.get("clean") is True)
        check("no configs: empty configs", bool(data) and data.get("configs") == [])
        human = run(["doctor"], env, project)
        check("no configs: human message", "No supported MCP client configs found" in human.stdout, human.stdout)


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    case_clean()
    case_not_wrapped()
    case_remote()
    case_not_allowlisted()
    case_allowlist_not_enforced()
    case_hash_mismatch()
    case_risky_scratch_home()
    case_risky_scratch_repo()
    case_safe_scratch()
    case_trust_on_egress()
    case_trust_safe()
    case_approvals_off()
    case_pins_unreadable()
    case_unsigned()
    case_outdated_metadata()
    case_outdated_binary()
    case_guard_not_found()
    case_guard_version_unknown()
    case_wrapper_invalid()
    case_policy_invalid()
    case_broken_config()
    case_server_invalid()
    case_no_leak()
    case_read_only()
    case_usage()
    case_no_configs()
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
