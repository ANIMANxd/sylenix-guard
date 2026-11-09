"""Run the ten tainted-call probes from test_scratch_grant_bypass.py with and
without --allow-write-under. Evaluation harness only; not product code.
"""
import importlib.util
import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests" / "probes"))
spec = importlib.util.spec_from_file_location(
    "scratch_probes", ROOT / "tests" / "probes" / "test_scratch_grant_bypass.py")
probe_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe_mod)

OUT = pathlib.Path(__file__).resolve().parent
records = []
summary = []

for mode, flags in (("baseline", ()), ("allow-write-under", ("--allow-write-under",))):
    with tempfile.TemporaryDirectory(prefix="sylenix-outside-") as d:
        out = os.path.join(d, "out")
        os.mkdir(out)
        actual_flags = list(flags)
        if mode == "allow-write-under":
            actual_flags = ["--allow-write-under", out]
        s = probe_mod.Session(d, flags=tuple(actual_flags))
        s.start()
        s.call("read_ticket")
        blocked = 0
        for label, args, expected in probe_mod.probes(out):
            r = s.call("write_file", args)
            rule = probe_mod.rule(r)
            is_blocked = "result" not in r
            blocked += is_blocked
            records.append({
                "mode": mode,
                "label": label,
                "expected_rule": expected,
                "actual_rule": rule,
                "blocked": is_blocked,
                "response": r,
            })
        code = s.close()
        summary.append({"mode": mode, "probes": 10, "blocked": blocked,
                        "guard_exit": code, "scratch": out if mode == "allow-write-under" else ""})
        # Keep the Guard audit log for the mode.
        src = pathlib.Path(d) / "audit-probe.jsonl"
        if src.exists():
            (OUT / f"audit-{mode}.jsonl").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

with open(OUT / "probes.jsonl", "w", encoding="utf-8", newline="\n") as fh:
    for rec in records:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")

lines = ["outside 10-probe set", ""]
for row in summary:
    lines.append(f"{row['mode']}: {row['blocked']}/{row['probes']} blocked; guard exit {row['guard_exit']}")
lines.append("")
lines.append("Every probe is expected to be blocked. See probes.jsonl for the exact rule per probe.")
(OUT / "probes-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
