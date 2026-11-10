# SPDX-License-Identifier: Apache-2.0

"""Regression probes for Ed25519 policy and pin signing.

Covers key generation, detached policy signatures, fail-closed startup on an
unsigned or one-byte-tampered policy, automatic pin signing on write, pin
tamper detection, unsigned-pin rejection, and the team-public-key mode.

Run after building the guard:
    python3 tests/probes/test_signing.py
"""
import json
import os
import subprocess
import sys
import tempfile

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


def run(args, timeout=15):
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)


POLICY = """version: 1
approval: deny
servers:
  t:
    tools:
      read_ticket:
        class: read
"""


def write_policy(path):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(POLICY)


def init_keys(keys_dir):
    return run([GUARD, "keys", "init", "--out", keys_dir])


def key_paths(keys_dir):
    priv = os.path.join(keys_dir, "policy-signing.key")
    return priv, priv + ".pub"


def start_guard(args):
    return subprocess.Popen(
        [GUARD] + args + ["--", sys.executable, FAKE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def send(proc, obj):
    proc.stdin.write(json.dumps(obj, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def recv(proc):
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("guard closed stdout")
    return json.loads(line)


def initialize_and_list(proc):
    send(proc, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "signing-probe", "version": "0"}},
    })
    recv(proc)
    send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    return recv(proc)


def close_guard(proc):
    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()


def test_keys_init():
    print("key generation")
    with tempfile.TemporaryDirectory() as d:
        keys = os.path.join(d, "keys")
        p = init_keys(keys)
        priv, pub = key_paths(keys)
        check("keys init exits 0", p.returncode == 0, p.stderr)
        check("private key exists", os.path.exists(priv))
        check("public key exists", os.path.exists(pub))
        check("keys init warns about the private key", "WARNING" in p.stderr and "private key" in p.stderr.lower(), p.stderr)
        check("keys init prints the public path", "public key" in p.stdout and pub in p.stdout, p.stdout)

    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state")
        os.makedirs(state)
        p = run([GUARD, "keys", "init", "--out", os.path.join(state, "keys"), "--state-dir", state])
        check("keys init refuses a key inside the state dir", p.returncode == 2 and "state directory" in p.stderr, p.stderr)


def test_policy_signing():
    print("policy signatures")
    with tempfile.TemporaryDirectory() as d:
        keys = os.path.join(d, "keys")
        state = os.path.join(d, "state")
        os.makedirs(state)
        init_keys(keys)
        priv, pub = key_paths(keys)
        policy = os.path.join(state, "policy.yaml")
        write_policy(policy)

        unsigned = run([GUARD, "--name", "t", "--state-dir", state, "--policy", policy,
                        "--policy-pubkey", pub, "--", sys.executable, FAKE])
        check("unsigned policy is rejected when signing is enabled",
              unsigned.returncode == 2 and "signature" in unsigned.stderr.lower(), unsigned.stderr)

        p = run([GUARD, "policy", "sign", "--policy", policy, "--key", priv])
        check("policy sign exits 0", p.returncode == 0, p.stderr)
        check("policy signature exists", os.path.exists(policy + ".sig"))
        check("policy signature is 64 bytes", os.path.getsize(policy + ".sig") == 64)
        verify = run([GUARD, "policy", "verify", "--policy", policy, "--pubkey", pub])
        check("policy verify accepts the signature", verify.returncode == 0, verify.stderr)

        with open(policy, "rb") as fh:
            original = fh.read()
        tampered = bytearray(original)
        tampered[0] ^= 1
        with open(policy, "wb") as fh:
            fh.write(tampered)
        bad = run([GUARD, "--name", "t", "--state-dir", state, "--policy", policy,
                   "--policy-pubkey", pub, "--", sys.executable, FAKE])
        check("one-byte policy tamper is rejected",
              bad.returncode == 2 and "signature" in bad.stderr.lower(), bad.stderr)
        with open(policy, "wb") as fh:
            fh.write(original)

        os.remove(policy)
        missing = run([GUARD, "--name", "t", "--state-dir", state,
                       "--policy-pubkey", pub, "--", sys.executable, FAKE])
        check("deleting the auto-loaded policy fails closed",
              missing.returncode == 2 and "missing" in missing.stderr.lower(), missing.stderr)
        write_policy(policy)
        run([GUARD, "policy", "sign", "--policy", policy, "--key", priv])

        proc = start_guard(["--name", "t", "--state-dir", state, "--policy", policy, "--policy-pubkey", pub])
        try:
            reply = initialize_and_list(proc)
            check("signed policy starts and tools/list works", "result" in reply, str(reply)[:160])
            check("public-key-only mode does not write an unsigned pin file",
                  not os.path.exists(os.path.join(state, "pins-t.json")))
        finally:
            close_guard(proc)


def test_pin_signing():
    print("pin signatures")
    with tempfile.TemporaryDirectory() as d:
        keys = os.path.join(d, "keys")
        state = os.path.join(d, "state")
        os.makedirs(state)
        init_keys(keys)
        priv, pub = key_paths(keys)
        policy = os.path.join(state, "policy.yaml")
        write_policy(policy)
        run([GUARD, "policy", "sign", "--policy", policy, "--key", priv])

        proc = start_guard(["--name", "t", "--state-dir", state, "--policy", policy, "--policy-key", priv])
        try:
            reply = initialize_and_list(proc)
            check("private-key mode starts and tools/list works", "result" in reply, str(reply)[:160])
        finally:
            close_guard(proc)

        pins = os.path.join(state, "pins-t.json")
        sig = pins + ".sig"
        check("pin file exists after tools/list", os.path.exists(pins))
        check("pin signature exists after tools/list", os.path.exists(sig))
        verify = run([GUARD, "pins", "verify", "--name", "t", "--state-dir", state, "--pubkey", pub])
        check("pins verify accepts the signature", verify.returncode == 0, verify.stderr)

        with open(pins, "rb") as fh:
            original = fh.read()
        tampered = bytearray(original)
        tampered[0] ^= 1
        with open(pins, "wb") as fh:
            fh.write(tampered)
        bad = run([GUARD, "--name", "t", "--state-dir", state, "--policy", policy,
                   "--policy-key", priv, "--", sys.executable, FAKE])
        check("one-byte pin tamper is rejected",
              bad.returncode == 2 and "signature" in bad.stderr.lower(), bad.stderr)
        with open(pins, "wb") as fh:
            fh.write(original)

        os.remove(sig)
        unsigned = run([GUARD, "--name", "t", "--state-dir", state, "--policy", policy,
                        "--policy-pubkey", pub, "--", sys.executable, FAKE])
        check("unsigned pin file is rejected",
              unsigned.returncode == 2 and "signature" in unsigned.stderr.lower(), unsigned.stderr)

        signed = run([GUARD, "pins", "sign", "--name", "t", "--state-dir", state, "--key", priv])
        check("pins sign restores the signature", signed.returncode == 0, signed.stderr)
        verify = run([GUARD, "pins", "verify", "--name", "t", "--state-dir", state, "--pubkey", pub])
        check("pins verify accepts the restored signature", verify.returncode == 0, verify.stderr)


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    test_keys_init()
    test_policy_signing()
    test_pin_signing()
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
