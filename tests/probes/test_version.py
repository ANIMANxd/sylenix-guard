# SPDX-License-Identifier: Apache-2.0

"""Version output probes for `--version` and the `version` subcommand.

The test also puts a fake executable named `version` on PATH. If the guard
treated the subcommand as a server command, that executable would run and
create the marker file.

Run after building the guard:

    python3 tests/probes/test_version.py
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GUARD = os.environ.get("SYLENIX_GUARD") or os.path.join(
    ROOT, "bin", "sylenix-guard.exe" if sys.platform == "win32" else "sylenix-guard")

EXPECTED = re.compile(r"^sylenix-guard 0\.1\.1 \((?:[0-9a-f]{7,40}|unknown), go1\.[0-9.]+\)$")

passed, failed = 0, []


def check(label, cond, detail=""):
    global passed
    if cond:
        passed += 1
        print(f"  ok   {label}")
    else:
        failed.append(label)
        print(f"  FAIL {label} {detail}")


def run(args, env=None):
    return subprocess.run([GUARD, *args], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=10, env=env)


def check_output(label):
    p = run([label])
    lines = p.stdout.strip().splitlines()
    check(f"{label}: exit 0", p.returncode == 0, p.stderr)
    check(f"{label}: one line", len(lines) == 1, p.stdout)
    check(f"{label}: format", bool(lines) and bool(EXPECTED.match(lines[0])),
          lines[0] if lines else p.stdout)
    check(f"{label}: no stderr", p.stderr == "", p.stderr)
    return p.stdout


def main():
    print("version output")
    flag_out = check_output("--version")
    sub_out = check_output("version")
    check("--version and version agree", flag_out == sub_out, f"{flag_out!r} != {sub_out!r}")

    print("version is not launched as a server")
    with tempfile.TemporaryDirectory() as td:
        marker = os.path.join(td, "launched")
        if sys.platform == "win32":
            fake = os.path.join(td, "version.cmd")
            body = f'@echo launched>"{marker}"\r\n@exit /b 99\r\n'
        else:
            fake = os.path.join(td, "version")
            body = f'#!/bin/sh\nprintf launched > "{marker}"\nexit 99\n'
        with open(fake, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
        if sys.platform != "win32":
            os.chmod(fake, 0o755)
        env = dict(os.environ)
        env["PATH"] = td + os.pathsep + env.get("PATH", "")
        p = run(["version"], env=env)
        check("version: exit 0 with fake server on PATH", p.returncode == 0, p.stderr)
        check("version: fake server was not executed", not os.path.exists(marker), marker)
        check("version: output is still the version", p.stdout.strip() == sub_out.strip(), p.stdout)

    print()
    if failed:
        print(f"{len(failed)} failed:")
        for name in failed:
            print(f"  - {name}")
        return 1
    print(f"{passed} passed, 0 failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
