# Audit 2 — Re-audit of the fixed guard (Wave 1D)

**Status update (2026-10-31).** AUD-10 is fixed: `loadPins` now refuses a pin file whose
values are not 64-character hex SHA-256 strings, and the self-test has fixtures for a
`null` value, a non-hex value and an empty tool name. AUD-09 is mitigated for
newline-terminated frames (the 64 MiB discard budget and the fatal `FRAME_TOO_LARGE`
path); an unterminated oversize line can still stall until EOF, which is an availability
residual, not a confidentiality one. AUD-08 remains the documented grandchild-process
limitation. The findings below are the original audit record.

Date: 2026-10-11. Target: `bin/sylenix-guard` built from the Wave 1C tree
(commit `484d5bf`, sha256 `2264fa45c2e36e5c4691fb27d52fe0f7197739275b54c256092e56cca60358e4`),
run under WSL2 Ubuntu (Linux); `make check` green (68 passed, 0 failed) before
starting. This is a read-only re-audit: no repository file was created or
modified other than this document, and probe scripts lived under `/tmp/probes/`
(`hs.py`, `idfmt_server.py`, `datamark_server.py`, `crlf_server.py`,
`oversize_server.py`, `trust_server.py`, `exits3_server.py`, `unicode_server.py`,
`p1.py`, `p2.py`, `p3.py`). Procedures from docs/AUDIT_1.md were reused: the
guard sat in front of `demo/fake_server.py` via a `Session` helper cloned from
`demo/selftest.py`, or in front of a purpose-built fake server where AUDIT_1
used one. Every number below comes from a real run; probe scripts were run
twice where behaviour was timing-sensitive.

## (a) Probe table

| # | Verdict | Evidence (exact behavior observed) |
|---|---|---|
| 1 | PASS | `tools/call` id 3 answered by the server with id `1.0` (run 2: id `"1"`). Reply forwarded unchanged (`SUSPECT-1.0` / `SUSPECT-1`, no wrapper, as designed for unmatched responses); audit `unmatched_response=1 taint_latched=1`; the next `write_file` returned `-32000 TAINT_SINK`. AUD-01 is fixed. |
| 4 | PASS | A valid `ping` padded to exactly 10 MiB was accepted and answered (id 70, `result`, 0.16 s). The AUDIT_1 trigger bytes `b"x"*(10*1024*1024+1)` + `\n` produced `-32600`, rule `FRAME_TOO_LARGE`, `"id": null` in 0.03 s; a `ping` afterwards still worked; guard exit 0. AUD-02 host side fixed for newline-terminated lines. |
| 6 | PASS | Server did `os.close(1)` and slept: the pending `tools/call` got `-32000 SERVER_STREAM_CLOSED`, a later `ping` got the same instead of being dropped; audit `server_stream_closed=1 pending_failed=1`; guard exit 1 after 5.0 s (kill timer). AUD-03 fixed. |
| 10 | PASS | Two `tools/call` with id 1 (`read_ticket`, then `write_file`): the second was refused `-32600`, rule `DUPLICATE_ID`, `"id": null`; the first reply was datamarked `origin="read_ticket"` (correct origin); server call log `['read_ticket']` — the refused call never reached the server. AUD-04 fixed. |
| 11 | PASS | All seven AUDIT_1 code points now quarantine `write_file` with `-32001`: U+00AD, U+061C, U+180E, U+2028, U+2029, U+115F, U+3164. AUD-05 fixed. |
| 12 | PASS | Healthy pins (732 bytes) overwritten with `{corrupted json`: restart exited 2 in 0.03 s; the only new audit events were `pins_unreadable` (zero `start` events — server never launched); stderr: `[sylenix-guard] pin file …/pins-t.json exists but cannot be read; refusing to start…`. AUD-06 fixed. |
| 13 | PASS | Rich reply (text with U+200B/U+202C, heart+VS16, ZWJ family emoji; image; resource; `isError:true`; 2 MB text; `structuredContent` with RLO, zero-widths, big int): text wrapped once in `<untrusted_tool_result origin="mixed" integrity="untrusted">` with invisibles stripped and emoji preserved; image/resource items unchanged; `isError` preserved; 2 MB item wrapped; `structuredContent` **stripped** (`note='smuggle <b>bold</b>  sneaky'`, `arr[1]=='xy'`, `arr[2].k=='vk'`), **not wrapped**, `big == 12345678901234567890` exactly. AUD-07 fixed as designed. |
| 14 | PASS | 8 threads sent 5,000 mixed frames (2,000 blocked `write_file`, 2,000 `read_ticket`, 1,000 `ping`) in 0.6 s after tainting: replies 5,000/5,000, all valid JSON; audit `block(TAINT_SINK)=2000 allow=2001 taint_latched=1`; guard exit 0. No regression. |
| 16 | PASS | Host frames with `\r\n`, server replied with `\r\n`: initialize and tools/list OK; `read_ticket` datamarked (U+200B stripped); `write_file` `TAINT_SINK`; `ping` `result`; every reply parsed; exit 0. No regression. |
| 17a | PASS | Server printed one line of 10 MiB + 1 bytes (terminated) then answered: the pending request failed `-32000`, rule `SERVER_FRAME_TOO_LARGE`, in 0.03 s; audit `server_frame_too_large=1 pending_failed=1`; the server's late answer then arrived as an unmatched response (forwarded unchanged, taint already latched — fail closed); a later `ping` was answered; taint latched (`write_file` → `TAINT_SINK`); guard exit 0. |
| 17b | PASS (with finding) | Server printed 70 MiB with **no newline** and stayed alive: while the server lived, the guard produced nothing within 2.5 s — the pending request was held and the stream stalled (see AUD-09). After the server exited, the pending id got `-32000 SERVER_STREAM_CLOSED`, guard exit 0 at 4.2 s, no hang. The oversize condition itself was never reported (`server_frame_too_large=0`). |
| 18a | **FAIL** | Host wrote 70 MiB with **no newline**, stdin held open: the guard consumed the write in 0.10 s but emitted **no frame** within 5.1 s; on stdin close the host saw a **silent EOF with zero frames** and guard exit 0 — AUDIT_1's AUD-02 signature, still reachable. See AUD-09. |
| 18b | PASS | Host wrote 80 MiB with no newline (past the discard budget): exactly one `-32600 FRAME_TOO_LARGE` frame with `"id": null` in 0.13 s, the guard tore the session down while the host was still writing (host write hit `BrokenPipe`), then EOF and exit 0. Orderly, no hang. |
| 18c | PASS | 70 MiB **with** a newline: one `-32600 FRAME_TOO_LARGE`, `"id": null`, in 0.12 s; `ping` after still answered; guard exit 0. |
| 19 | PASS | Eight `tools/call` left pending at `close_stdout` with ids `"a\"b"`, `-0`, `1e3`, `1234567890123456789012345`, `null`, `{"a":1}`, `[1]`, `true`: exactly 8 frames came back, every one valid JSON, every id echoed **verbatim** (`"id":1e3`, the 25-digit number intact, `"id":null`, `"id":{"a":1}`, `"id":[1]`, `"id":true`, `"id":"a\"b"`, `"id":-0` — raw frames in probe state `p19b/frames.txt`); all rules `SERVER_STREAM_CLOSED`; guard exit 1 in ~5 s; no panic in stderr; audit `pending_failed=1 server_stream_closed=1`. |
| 20 | PASS | `--trust write_file`; slow `read_ticket` (id 5) in flight when `write_file` reused id 5: second refused `-32600 DUPLICATE_ID` with `"id": null`; first reply arrived wrapped `<untrusted_tool_result origin="read_ticket"…` containing `SUSPECT-TRUST-BYPASS`; server saw only `['read_ticket']`; a later `write_file` → `TAINT_SINK`; audit `taint_latched=1`. The AUD-04 trust-bypass chain is dead. |
| 21 | PASS | Healthy pins, server then serves a changed `write_file` description, guard restarted with `--reset-pins`: audit `pins_reset=1`, `tool_quarantined=0`; the changed tool was accepted as new and re-pinned with a new hash; `read_ticket` still datamarked; `write_file` after taint still `TAINT_SINK`; exit 0. No other change in behavior. |
| 22 | **FAIL** (1 of 6 shapes) | `{"write_file": 5}`, `"text"`, `0` → exit 2 in ≤0.03 s with `pins_unreadable` and no `start` event (as expected). **`{"write_file": null}` → guard started, exit 0** (see AUD-10); follow-up probe: the null became an empty-string pin, so the next tools/list quarantined `write_file` (`-32001 MANIFEST_QUARANTINE`, audit reason `definition changed since it was pinned`) while `read_ticket` worked. A valid 20.0 MB pin file was accepted and the guard started in 0.18 s (vs 0.04 s for a 70-byte file) — no slowness of note. |
| 23 | PASS | (a) server exited 3 without replying: host got `-32000 SERVER_STREAM_CLOSED` for the pending call then EOF, guard exit **3** in <0.01 s. (b) hung server killed by the timer: guard exit **1** after 5.0 s. (c) SIGTERM to an idle guard: exit **1** in 0.02 s. All three exit codes as specified. |
| 24 | INFO | Family emoji built with ZWJ came out as `U+1F468 U+1F469 U+1F467 U+1F466` — the three ZWJs are stripped, so one 👨‍👩‍👧‍👦 becomes four separate emoji. Persian `U+0645 U+06CC U+200C U+062E U+0648 U+0627 U+0647 U+0645` came out without the ZWNJ (`…U+06CC U+062E…`), fusing the word parts. This is the documented cost of the locked stripping rule (POC_SPIKE section 7); stripping never *adds* characters and no bidi or tag character survived. |
| 25 | PASS | Unique `AUD2MARK-*` marker strings were sent as argument values in every probe that carried arguments (probes 1, 6, 10, 11, 13, 14, 16, 17, 19b follow-up, 20, 21, 22 follow-up, 23, 24). Final scan: 105 audit/stderr/pin files under the probe state root, `grep -r AUD2MARK` → **0 matches**. The guard logged no argument values anywhere. |

## (b) Findings

### AUD-09 — Medium — An oversize line with no newline inside the discard envelope stalls the stream silently, and EOF mid-oversize-line emits nothing

Trigger (exact bytes): host side — 73,400,320 bytes of `z` (70 MiB) with no
newline written to the guard's stdin, stdin held open for 5 s, then closed.
Server side — the server writes 73,400,320 bytes of `y` (70 MiB) with no
newline and keeps running (probe 17b). Contrast: 83,886,080 bytes (80 MiB,
past the budget) is handled correctly (probe 18b), and 70 MiB *with* a
newline is handled correctly (probe 18c).
Expected (per the locked AUD-02/AUD-03 decisions): one `-32600`
`FRAME_TOO_LARGE` frame with id null and an orderly shutdown on the host side;
on the server side, taint plus `SERVER_FRAME_TOO_LARGE` failures for pending
requests, or at minimum no silent stall.
Actual: `readFrame` counts discard budget only from the chunk that crosses the
10 MiB limit, so a no-newline line is tolerated up to roughly 74 MiB before
`broken` triggers; below that the guard simply waits inside `ReadLine`. With
the stream still open nothing is emitted and no taint latches: the pending
request hangs and (server side) all server→host traffic stops with no signal —
an AUD-03-shaped stall reachable again by other means. When the stream then
ends, the `err != nil` branch of both read loops breaks out **before**
examining the returned `tooLong` flag, so the host saw zero frames and a bare
EOF (probe 18a) — the exact silent-death signature AUD-02 was fixed for, still
reachable in the 10 MiB–74 MiB no-newline window.
Proposed fix: make the decision at the crossing point, not at the end of the
discard. As soon as `readFrame` marks a line `tooLong`, let the caller act —
host side emit the `FRAME_TOO_LARGE` frame immediately and only then keep
discarding for framing; server side latch taint and fail pending requests with
`SERVER_FRAME_TOO_LARGE` immediately — and keep discarding purely as a
framing exercise. Separately, when `readFrame` returns an error while
`tooLong` is set, treat the stream as unframable (the same path as `broken`:
one final error frame / stream-closed teardown) instead of breaking silently.
Optionally charge the buffered first 10 MiB against `discardBudget` so the
documented budget means total discarded bytes. Covered by self-test cases for
"a no-newline oversize line smaller than the budget" on both sides.

### AUD-10 — Medium — A pin file with JSON `null` values starts the guard and bricks the named tools instead of refusing to start

Trigger (exact bytes): `pins-<name>.json` containing `{"write_file": null}`
(19 bytes), then a normal guard start against `demo/fake_server.py`.
Expected (the AUD-06 locked rule, extended: exit 2 for every shape that is not
an object of strings): the guard refuses to start with exit 2 before any
server is launched, because `null` is not a string.
Actual: the guard started (exit 0, 0.04 s, `start` event logged, no
`pins_unreadable`). `loadPins` accepts the file because Go's JSON decoder
treats a `null` value for a string-map entry as "leave the zero value" rather
than a type error, so `write_file` ends up pinned to the empty string. On the
next `tools/list` the real hash does not match the empty pin, so the tool is
quarantined with audit reason `definition changed since it was pinned` and
every call returns `-32001 MANIFEST_QUARANTINE` (probe 22 follow-up), while
tools not named in the file are unaffected. A 19-byte write by anything with
access to the state directory can therefore disable chosen tools of every
future session, with no startup refusal to alert a human — the same
tamper surface AUD-06 closed for corrupt files, open again for well-formed
files with wrong value types. The failure is fail-closed (the changed
definition still cannot execute), hence Medium rather than High.
Proposed fix: in `loadPins`, stop decoding straight into `map[string]string`.
Decode into `map[string]json.RawMessage` (or `any`) and reject the file —
exit 2 with the existing `pins_unreadable` event and "refusing to start"
message — unless every value unmarshals successfully as a JSON string; keep
`null`-the-whole-file, lists, scalars, and empty files in the same refusal
path as today, and keep `--reset-pins` as the only recovery. Add self-test
fixtures for `{"tool": null}` next to the existing corrupt/`null`/list/empty
fixtures.

## Summary

All seven Wave 1C fixes held under re-audit: AUD-01 (unmatched responses now
latch taint), AUD-02 (host oversize frames — newline-terminated path), AUD-03
(server stdout closure), AUD-04 (duplicate ids, including the `--trust`
bypass chain), AUD-05 (all seven previously missed code points), AUD-06
(corrupt pin file refuses to start), AUD-07 (`structuredContent` stripped,
numbers exact). No probe found a way for content to reach the host without
either the datamark wrapper or a latched taint, and probe 25 confirms the
audit logs still carry no argument values. Two new findings, both Medium,
both fail toward availability rather than confidentiality: AUD-09 (the
no-newline oversize window still allows a silent stall / silent EOF, a
residual of AUD-02/AUD-03) and AUD-10 (`null` pin values accepted at startup,
bricking the named tools). AUD-08 (grandchild processes) was not re-tested:
it is unchanged and remains a documented limitation.
