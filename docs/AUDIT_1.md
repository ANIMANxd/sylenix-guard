# Audit 1 — Adversarial audit of the Sylenix Guard POC (Wave 1B)

Date: 2026-10-11. Target: `bin/sylenix-guard` built from the Wave 0 tree
(commit `3f2cba8`), run under WSL2 Ubuntu 26.04 (Linux), `make check` green
(23 passed, 0 failed) before starting. Every probe was executed for real; the
guard sat in front of `demo/fake_server.py` (via the `demo/selftest.py`
`Session` helper) or a purpose-built fake server under `/tmp/probes/`. No
repository file was modified by this audit other than this document.

## (a) Probe table

| # | Verdict | Evidence (exact behavior observed) |
|---|---|---|
| 1 | FAIL | Sent `{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_ticket", "arguments": {}}}`; server answered with id `1.0` (run 2: id `"1"`) and text `SUSPECT-1.0`. Reply reached the host unmarked, audit `unmatched_response=1 taint_latched=0`, and a subsequent `write_file` was FORWARDED, not blocked. See AUD-01. |
| 2 | PASS | Tainted session (`--readonly read_ticket`): `write_file`, `Write_File`, `" write_file"`, `write_file<U+200B>`, `write_file<U+0000>` all returned `-32000 TAINT_SINK`; server call log stayed empty for them. Clean session: all five forwarded to the server. Tainted with `--readonly write_file`: only the exact name `write_file` produced a result (`server_saw=['read_ticket', 'write_file']`); the other four were `TAINT_SINK`. |
| 3 | PASS | params-as-array, params-missing, name-as-number, name-empty, arguments-as-string, arguments-as-array: each `-32000 UNPARSEABLE_CALL` with the request id echoed (91–96). `arguments omitted` in a clean session: forwarded, result returned, and it was the only call the server saw (`['read_ticket']`). Ping afterwards succeeded. |
| 4 | FAIL | Wrote one line of exactly 10 MiB + 1 byte (`b"x"*(10*1024*1024+1)` + `\n`). Host write completed (0.042 s); the guard sent **no error frame**; host saw EOF 0.004 s later; guard exited 0. Audit: `host_read_error=1`. The whole session died silently for one oversized line. See AUD-02. |
| 5 | PASS | 200,000 non-JSON lines from the server drained through the guard in 0.4 s; guard `VmHWM=8540 kB`, `VmRSS=7872 kB`; audit `taint_latched=1`, `unparseable_server_frame=200000`; a `ping` sent after the flood was answered (`result: {}`). |
| 6 | FAIL | Server did `os.close(1)` then slept 60 s. The guard produced no output and no EOF within 8 s, stayed alive, and silently dropped a `ping` sent in between. Only after the host closed stdin did the guard kill the server and exit — code 255, 5.0 s later. With stdin open this is an unbounded hang with all traffic dropped. See AUD-03. |
| 7 | PASS | Server answered a `tools/call` by exiting with code 3 without replying. Host saw EOF 0.001 s after the call; guard exited 3 (server's code). Well under 2 s. |
| 8 | PASS | Host closed stdin immediately after a `tools/call` whose server replies after 3 s. The pending reply still reached the host (datamarked `<untrusted_tool_result origin="read_ticket"…`, re-encoded as valid JSON), then EOF; guard exit 0 at 3.01 s total (< 6 s). |
| 9 | INFO | SIGTERM to an idle guard: exit status 1, immediate. With a fake server that spawned `sleep 60` (pid 468): the grandchild survived the guard's death (`pgrep` found 468 afterwards). Confirms the documented "process cleanup is minimal" limitation (POC_SPIKE.md section 7). See AUD-08 (Low, documented). |
| 10 | PASS (with finding) | Two `tools/call` with `id 1` (`read_ticket` then `write_file`) sent before any reply. No panic; guard stayed up (ping OK); audit `unmatched_response=1 taint_latched=1`; final `write_file` blocked `TAINT_SINK`. But reply 1 was datamarked with the **wrong origin** (`write_file`, the value that had overwritten pending id 1) and reply 2 was forwarded **without** datamark. See AUD-04. |
| 11 | FAIL | Description `"Write a file." + <char>`: U+00AD, U+061C, U+180E, U+2028, U+2029, U+115F, U+3164 were all **NOT quarantined** (call forwarded, result returned). Positive control U+200B: QUARANTINED. See AUD-05. |
| 12 | FAIL | After run 1 pinned the tools, the pin file was overwritten with `{corrupted json`. On restart with a changed `write_file` description, audit showed `pins_unreadable=1` and `tool_quarantined=0`; the changed tool was **accepted** and executed. See AUD-06. |
| 13 | PASS (with finding) | Reply with text/image/resource items, `isError: true`, `structuredContent`, U+202C/U+200B/U+202E content, emoji, and a 2 MB text item: output re-parsed as valid JSON; text item wrapped in `<untrusted_tool_result origin="mixed" integrity="untrusted">` with exactly one closing tag; U+200B and U+202C stripped from it; emoji preserved; image and resource items byte-identical; `isError` preserved; 2 MB item wrapped (len 2,097,236). `structuredContent` was passed through **verbatim and unmarked**, RLO (U+202E) inside it intact. See AUD-07. |
| 14 | PASS | 8 threads sent 5,000 mixed frames (2,000 blocked `write_file`, 2,000 forwarded `read_ticket`, 1,000 `ping`) in 0.2 s after tainting. Replies: 5,000, all parse as JSON, 0 unparseable, none missing. Audit `block=2000 allow=2001 taint_latched=1`; guard exit 0. |
| 15 | PASS | `tools/call` response `{"jsonrpc":"2.0","id":3,"error":{"code":-32603,"message":"internal boom"}}` (no `result`) was forwarded unchanged, audit `taint_latched=1`, and the next `write_file` was blocked `TAINT_SINK`. Error responses fail closed as intended. |
| 16 | PASS | All host frames sent with `\r\n` endings, server replied with `\r\n`: initialize, tools/list, read_ticket (datamarked), write_file (blocked `TAINT_SINK` when tainted), ping — every reply parsed, every rule held, exit 0. |

## (b) Findings

### AUD-01 — High — Response with an unmatched id bypasses taint and datamarking

Trigger (exact bytes): host sends `{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_ticket", "arguments": {}}}`; server replies `{"jsonrpc": "2.0", "id": 1.0, "result": {"content": [{"type": "text", "text": "SUSPECT-1.0"}]}}` (or `"id": "1"` — any id whose raw bytes differ from the tracked `"3"`).
Expected (per the fail-closed model): the reply is forwarded, taint latches via `unmatched_response`, and `write_file` is then blocked.
Actual: reply forwarded **unmarked**, audit `unmatched_response=1 taint_latched=0`, and `write_file` executed with a clean session (`{... "result": {"content": [{"text": "wrote"}]}}`). A malicious or compromised server (threat A2) can therefore deliver arbitrary injected content that never latches taint, leaving every sink open — a secret can leave on the very next call.
Proposed fix: in `fromServer`, when `take()` misses, latch taint before returning the line (fail closed), exactly as the unparseable-output path already does — an id the guard never issued is attacker-shaped data, not a benign response. Keep forwarding the frame unchanged and keep the `unmatched_response` audit event; optionally record the id mismatch class (number vs string) in the audit only. This is the F1 decision and should be shipped with the ghost-server test already drafted in Wave 1A.

### AUD-02 — High — One oversized host line kills the whole session with no error to the host

Trigger (exact bytes): a single line of `b"x" * (10*1024*1024 + 1)` followed by `\n` on the guard's stdin.
Expected: the frame is refused with a JSON-RPC error (it is not valid JSON-RPC anyway) and the session survives, or at minimum the host learns why the connection closed.
Actual: no reply at all; the host saw EOF 4 ms later; the guard exited 0. Only the audit recorded `host_read_error=1`. Legitimate in-flight requests and the entire session die silently — a High-severity self-DoS with no signal to the host or the model.
Proposed fix: distinguish "line too long" from other scanner errors. On overflow, discard input up to the next newline within a small byte budget, emit a `-32700`/`-32600` error frame with id null for the discarded frame, and keep both directions running; if the budget is exhausted (stream no longer framable), emit one error frame before tearing down so the host never sees a bare EOF. The audit event stays.

### AUD-03 — High — Guard hangs forever when the server closes stdout but stays alive

Trigger: a server that does `os.close(1)` and keeps running (e.g. sleeping); host keeps stdin open.
Expected: the guard treats loss of the server's output stream as the end of the mediated session — close the server's stdin, start the kill timer, exit — or at least reports the breakage to the host.
Actual: no EOF, no output, guard alive indefinitely; a `ping` sent afterwards was silently dropped (no reply, no error); the guard only exited after the host closed stdin, exiting 255 five seconds later via the kill timer. With stdin open (the normal state inside an agent host) this is an unbounded hang: all traffic is dropped without any error, and the host believes the session is healthy.
Proposed fix: when the server-stdout scanner hits EOF, immediately close the server's stdin, arm the existing kill timer, fail all pending requests with a JSON-RPC error (`-32000` or a dedicated "server stream closed" rule) so no request hangs forever, and let the process exit with the server's status once the server terminates or the timer fires. The stdin-side EOF path already does most of this; mirror it.

### AUD-04 — Medium — Duplicate host ids corrupt request/response matching

Trigger (exact bytes): `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_ticket","arguments":{}}}` immediately followed by `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{}}}`.
Expected: nothing panics; taint ends up correct; ideally the second request is refused.
Actual: no panic and taint did latch, but pending id `1` was overwritten, so the first server reply (the injected `read_ticket` content) was matched to `write_file` — it was datamarked with `origin="write_file"` (misattribution), and the second reply was forwarded raw via the unmatched path (no datamark). Worse, if `write_file` were listed in `--trust`, the guard's trust check (`g.trust[p.tool]`) would have seen `write_file` and forwarded the **read_ticket** content with neither taint nor datamark — a trust bypass that needs only a duplicate id.
Proposed fix: treat an in-flight id collision as a host protocol error — when `track()` finds an id already pending, refuse the second request with `-32600` (rule `DUPLICATE_ID`) and remove nothing; alternatively key pending entries by the id plus a sequence number and never let a later request inherit an earlier one's slot. Either way, a response must only ever carry the identity of the exact request it answers.

### AUD-05 — Medium — Hidden-character quarantine misses seven confusable/filler code points

Trigger (exact bytes): a `tools/list` whose `write_file` description is `"Write a file."` + U+00AD, U+061C, U+180E, U+2028, U+2029, U+115F, or U+3164 (one run each).
Expected: any hidden/invisible character in a tool definition quarantines the tool (`-32001`), as U+200B does.
Actual: none of the seven triggered quarantine; all seven definitions were pinned and the tool executed (positive control U+200B quarantined correctly). A hostile server can smuggle zero-width-looking fillers (U+115F, U+3164 render as blank), bidi-adjacent controls (U+061C) and line/paragraph separators (U+2028/U+2029, which also defeat naive line-oriented logging downstream) past the manifest check — a downgrade of Layer 0 that needs only a malicious server (A2).
Proposed fix: extend `isInvisible` to cover the Unicode format, separator and filler classes relevant to spoofing — at minimum the seven code points above, ideally general `Cf` plus U+2028/U+2029 and the Hangul fillers — and keep a small allowlist if some hosts legitimately use them. The same function feeds `stripInvisible` and `cleanForDialog`, so results and approval dialogs gain the same coverage for free; add fixtures per character to the protocol self-test.

### AUD-06 — Medium — Corrupt pin file silently resets trust and accepts a rug-pulled definition

Trigger (exact bytes): overwrite `pins-<name>.json` with `{corrupted json`, then start the guard against a server that serves a changed `write_file` description.
Expected: a tampered or unreadable pin file is a security-relevant event — the guard should fail closed (refuse to run, or run with the affected tools quarantined) and demand a human decision.
Actual: the guard logged `pins_unreadable=1`, started with an empty pin set, re-pinned the changed definition on first sight, and executed the tool (`tool_quarantined=0`). An attacker with local file access — or a server colluding with one — can wipe the pins and get any schema change accepted under TOFU with no visible consequence. The spike documents that pins are unsigned (section 7), but it does not document that *destroying* them is indistinguishable from never having seen the server.
Proposed fix: on an unreadable/corrupt pin file, do not silently fall back to an empty pin set. Refuse to start (or start with every tool quarantined and only `-32001` replies) until an explicit human action (`sylenix-guard --reset-pins` or similar) reinitializes the file, and raise a loud stderr alert plus an audit event. Trust-on-first-use should apply only to genuinely first sight, never to a file that exists but cannot be parsed.

### AUD-07 — Low — `structuredContent` bypasses datamarking and invisible-character stripping

Trigger (exact bytes): a `tools/call` result `{"content":[{"type":"text","text":"…"},…],"isError":true,"structuredContent":{"note":"smuggle <b>bold</b> <U+202E>"}}`.
Expected: every channel that reaches the model carries the untrusted wrapper, or at minimum invisible characters are stripped everywhere.
Actual: the text item was correctly wrapped and stripped; `structuredContent` was forwarded verbatim — no wrapper, and the RLO control (U+202E) survived inside it. Hosts that render `structuredContent` (or dump it into a log or a terminal) get unmarked, direction-controlled attacker text. Impact is limited today because the common clients render `content` blocks only, hence Low.
Proposed fix: during datamark, either wrap `structuredContent` values the same way as text items (preserving types, stripping invisibles), or strip invisible characters from all string values and add an explicit `untrusted` marker key; if neither is wanted, delete `structuredContent` from forwarded results when spotlighting is enabled and document that choice in POC_SPIKE.md section 7.

### AUD-08 — Low — SIGTERM kills the server but not its descendants (documented limitation, confirmed)

Trigger: a fake server that spawns `sleep 60` as a child; SIGTERM to the guard (pid recorded via `/proc`).
Expected (per POC_SPIKE.md section 7): the guard kills only the child it started; grandchildren survive.
Actual: guard exited 1 immediately; `sleep 60` (pid 468) was still alive afterwards. Matches the documented limitation — recorded here as confirmation, not a new defect. Proposed fix (when out of spike scope): start the server in its own process group (`Setpgid`) and signal the group, or wrap the child in a small supervisor that exits with the guard.

## Summary

3 High (AUD-01 latch bypass on unmatched responses, AUD-02 silent session death on oversized frames, AUD-03 unbounded hang on server stdout EOF), 3 Medium (AUD-04 duplicate-id identity corruption, AUD-05 hidden-character quarantine gaps, AUD-06 pin-file tamper resets TOFU), 2 Low (AUD-07 structuredContent not datamarked, AUD-08 grandchild survival — documented). No probe found a way for a *tainted* session to execute a non-read-only tool: every blocked path held under all name variants, malformed frames, error responses, CRLF, and 5,000-frame load. The High findings all involve the guard degrading or dying without telling the host, or content arriving through a path that never latches taint.
