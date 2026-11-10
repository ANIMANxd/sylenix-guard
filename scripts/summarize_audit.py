#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Summarize a sylenix-guard audit log (JSON lines).

    python3 scripts/summarize_audit.py --name filesystem
    python3 scripts/summarize_audit.py --file path/to/audit-x.jsonl

Active time counts only the gaps between consecutive events that are 600 seconds
or shorter, so idle periods do not dilute the prompts-per-hour figure.
"""
import argparse
import collections
import datetime
import json
import os
import re
import sys

GAP_LIMIT = 600
MIN_ACTIVE = 300
TS = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z$")


def parse_ts(s):
    m = TS.match(s)
    if not m:
        raise ValueError("bad timestamp: " + s)
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    micro = int((m.group(7) or "0")[:6].ljust(6, "0"))
    return datetime.datetime(y, mo, d, h, mi, se, micro, tzinfo=datetime.timezone.utc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", help="server name; reads ~/.sylenix-poc/audit-<name>.jsonl")
    ap.add_argument("--file", help="path to an audit log")
    a = ap.parse_args()
    if bool(a.name) == bool(a.file):
        sys.exit("give exactly one of --name or --file")
    path = a.file or os.path.expanduser(f"~/.sylenix-poc/audit-{a.name}.jsonl")
    rows = [json.loads(line) for line in open(path) if line.strip()]
    if not rows:
        sys.exit("audit log is empty")
    rows.sort(key=lambda r: parse_ts(r["ts"]))

    sessions, tainted_sessions, cur_tainted, open_ = 0, 0, False, False
    for r in rows:
        if r["event"] == "start":
            if open_ and cur_tainted:
                tainted_sessions += 1
            sessions += 1
            open_, cur_tainted = True, False
        elif r["event"] == "taint_latched":
            cur_tainted = True
        elif r["event"] == "exit":
            if open_ and cur_tainted:
                tainted_sessions += 1
            open_, cur_tainted = False, False
    if open_ and cur_tainted:
        tainted_sessions += 1

    times = [parse_ts(r["ts"]) for r in rows]
    active = sum(g for g in ((b - a_).total_seconds() for a_, b in zip(times, times[1:])) if g <= GAP_LIMIT)

    ev = collections.Counter(r["event"] for r in rows)
    blocks = collections.Counter((r.get("tool", "?"), r.get("rule", "?")) for r in rows if r["event"] == "block")
    appr = collections.defaultdict(lambda: [0, 0])
    for r in rows:
        if r["event"] == "approval":
            appr[r.get("tool", "?")][0 if r.get("granted") else 1] += 1
    granted = sum(v[0] for v in appr.values())
    denied = sum(v[1] for v in appr.values())
    quarantined = sorted({r.get("tool", "?") for r in rows if r["event"] == "tool_quarantined"})
    hours = active / 3600
    per_hour = "n/a (active time under 300 s)" if active < MIN_ACTIVE else f"{(granted + denied) / hours:.1f}"

    print(f"file: {path}")
    print(f"events: {len(rows)}   span: {rows[0]['ts']} -> {rows[-1]['ts']}")
    print(f"sessions: {sessions}  (tainted: {tainted_sessions})")
    print(f"active time: {hours:.2f} h   (gaps over {GAP_LIMIT} s excluded)")
    print(f"tool calls allowed: {ev['allow']}   blocked: {ev['block']}   approvals granted: {granted}   approvals denied: {denied}")
    print(f"approval prompts per active hour: {per_hour}")
    print("blocks by tool/rule:")
    for (tool, rule), n in sorted(blocks.items()):
        print(f"  {tool} {rule} : {n}")
    if not blocks:
        print("  none")
    print("approvals by tool:")
    for tool, (g, d) in sorted(appr.items()):
        print(f"  {tool} granted={g} denied={d}")
    if not appr:
        print("  none")
    print("tools quarantined: " + (", ".join(quarantined) if quarantined else "none"))
    print(f"unparseable server frames: {ev['unparseable_server_frame']}   unparseable host frames: {ev['unparseable_host_frame']}   server-initiated requests: {ev['server_request']}")


if __name__ == "__main__":
    main()
