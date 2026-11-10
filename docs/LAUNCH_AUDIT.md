# Launch audit — Sylenix Guard

**Audit date:** 2026-11-10
**Commit audited:** `5a1c520c035f6e0947f4751b991406728829ecd5` (`master`)
**Method:** read-only audit; no product code changed. Tests were run locally and
CI/API evidence was checked. This document is the only file created by the audit.

## Gate verdicts

| Gate | Verdict | Reason |
|---|---:|---|
| Security | **NO-GO** | No open policy bypass was found in the tested paths, but the declared cross-platform test gate is red on macOS and there is no release tag to prove test integrity against a previous release. |
| Friction | **NO-GO** | The replay target passes at **1.00 prompts/hour**, but the README clean-machine install path cannot work today: there are no tags/releases and the Homebrew tap and Scoop bucket URLs return 404. |
| Release integrity | **NO-GO** | No tag, GitHub release or downloadable asset exists, so the signed/verifiable artifact claim cannot be checked. GoReleaser/Cosign configuration is present but unexercised. |
| Documentation truth | **NO-GO** | Several current claims are false or stale, including install links, the architecture default port, and governance statements about package layout. |
| **Overall launch** | **NO-GO** | Security/platform evidence and the install/release path must be fixed or explicitly accepted before launch. |

---

## 1. Scope and baseline

- Audited HEAD: `5a1c520c035f6e0947f4751b991406728829ecd5`.
- `git tag --list` is empty.
- `git ls-remote --tags origin` returns no tags.
- GitHub API `repos/ANIMANxd/sylenix-guard/releases` returns **0 releases**.
- `results/2026-11-launch.md` records the November evaluation at commit
  `7305895c9f2026baf93eec9bf82309927143ef63`; that is the nearest evaluated
  baseline, not a Git tag.

Because there is no release tag, the requested “diff tests/ against the previous
release” check is formally **unverifiable**. For evidence, the audit compared
against the nearest evaluated commit, `7305895`:

```text
git diff --stat 7305895..HEAD -- tests/
 tests/probes/test_http_proxy.py           | 66 +++++++++++++++++
 tests/probes/test_policy.py               | 15 ++--
 tests/probes/test_protected_targets.py    | 117 +++++++++++++++++++++++++++++-
 tests/probes/test_scratch_grant_bypass.py | 29 ++++----
 4 files changed, 205 insertions(+), 22 deletions(-)
```

No test file was deleted. The diff adds coverage and tightens expected rules
(for example `.ssh` and home-relative SSH paths now expect the stricter
`SENSITIVE_TARGET` instead of `TAINT_SINK`) and separates test state directories.
This is not evidence for a formal release comparison; it is the best available
baseline.

## 2. Security gate

### 2.1 Local regression suite — PASS

`make check` on Windows at the audited commit exited **0**. All executed suites
passed:

| Suite | Result |
|---|---:|
| Protocol self-test, flags mode | 100 passed, 0 failed (1 dialog check skipped on Windows) |
| Protocol self-test, `--policy` mode | 100 passed, 0 failed |
| Scratch/grant bypass probes | 75 passed, 0 failed |
| Protected-target probes | 269 passed, 0 failed |
| Policy probes | 85 passed, 0 failed |
| Allowlist probes | 47 passed, 0 failed |
| Install probes | 67 passed, 0 failed |
| Streamable HTTP proxy probes | 27 passed, 0 failed |
| Signing probes | 23 passed, 0 failed |
| Profile probes | 62 passed, 0 failed |
| Doctor probes | 99 passed, 0 failed |
| Clear-taint probes | 64 passed, 0 failed |
| Stats probes | 21 passed, 0 failed |
| Team policy/audit Go tests | 3 packages passed (`auditevent`, `auditshipper`, `policyserver`) |

The audit did not find a failing adversarial probe or a policy bypass in these
paths. The Windows dialog check is skipped by design; the CI matrix is intended
to cover macOS/Linux.

### 2.2 CI matrix — FAIL (macOS)

GitHub Actions run
[`42798765577`](https://github.com/ANIMANxd/sylenix-guard/actions/runs/42798765577)
at the audited commit:

| Job | Conclusion |
|---|---|
| `make check (ubuntu-latest)` | success |
| `make check (windows-latest)` | success |
| `make check (macos-latest)` | **failure** |

The macOS job fails in the `make check` step at `team-test`:

```text
1222:FAIL	sylenix-guard-poc/teams/auditshipper	0.002s
1227:FAIL	sylenix-guard-poc/teams/policyserver	0.003s
1228:FAIL
1229:make: *** [team-test] Error 1
```

Public check annotations expose only the summary/tail, not the failing test
body, and the job log endpoint requires authenticated access. The exact macOS
failure is therefore unresolved; it must be reproduced on macOS before launch.
This is a launch blocker because the README claims macOS support and CI is the
only macOS test evidence.

### 2.3 Open bypass assessment

- **No open confidentiality/policy bypass found** in the local and CI-passing
  platforms.
- The known residual issues are availability/process cleanup, not policy
  bypasses:
  - **AUD-09 — Medium (availability):** an unterminated oversize line can stall
    the stream, and EOF mid-oversize-line can produce a silent EOF. Mitigated
    for newline-terminated frames; the no-newline window remains. Evidence:
    `docs/AUDIT_2.md` (AUD-09, probes 17b/18a).
  - **AUD-08 — Low:** SIGTERM kills the direct server process but not its
    descendants. Documented in `POC_SPIKE.md` section 7 and confirmed in
    `docs/AUDIT_1.md` (AUD-08).
- AUD-10 (`null` pin values) is fixed; `docs/AUDIT_2.md` updates the record.

## 3. Argument values and secrets — PASS

Evidence from code and tests:

- Local audit events are built by `Guard.event` in `cmd/sylenix-guard/main.go`;
  every tool-call audit call site records `arg_keys`, not `arguments`. Example:
  `g.event("block", ... {"arg_keys": argKeys(p.Arguments)})`.
- The shipped event schema in `teams/auditevent/event.go` has exactly seven
  fields: `timestamp`, `developer_id`, `server`, `tool`, `decision`,
  `reason_code`, `taint_state`. It has no argument/content/url/output field.
- `teams/auditevent` tests reject unknown fields, and
  `TestCollectorStoresExportsAndRejectsArguments` rejects a batch containing an
  `arguments` field.
- Existing checks passed:
  - `demo/selftest.py`: “audit log holds no argument values”.
  - `tests/probes/test_policy.py`: “audit holds no argument values”, “audit never
    stores hosts or bodies”.
  - `tests/probes/test_doctor.py`: no argument/env values in findings.
  - `tests/probes/test_http_proxy.py`: auth token not in state files.
  - `tests/probes/test_scratch_grant_bypass.py`: audit and bypass checks.
- Historical probe 25 in `docs/AUDIT_2.md` sent unique `AUD2MARK-*` argument
  markers and found **0 matches** across 105 audit/stderr/pin files.
- The dialog receives argument values to display to the human
  (`askHuman`), but that is an OS dialog, not an audit/event log; the audit
  record keeps only key names.

Configuration paths/commands (for example `--allow-write-under` roots, the
server command path and the redacted upstream host/path) appear in audit events.
These are configuration metadata, not tool argument values or secrets. No token,
`Authorization` header value, or tool output is written to the audit log.

## 4. Licence, security policy, contribution guide and SPDX — PARTIAL / FAIL

| Item | Status | Evidence |
|---|---|---|
| `LICENSE` | PASS | Apache License 2.0, 170 lines, copyright Sylenix Labs |
| `SECURITY.md` | PASS | Private reporting, bypass definition, response expectations, safe harbour |
| `CONTRIBUTING.md` | PASS (presence) | Present; content has stale package-layout claims (section 7) |
| Go SPDX headers | PASS | 15/15 Go files under `cmd/`, `teams/`, `demo/` carry `// SPDX-License-Identifier: Apache-2.0` |
| Python SPDX headers | **FAIL** | 24 Python files have no SPDX line: 6 under `demo/`, 6 under `scripts/`, 12 under `tests/probes/` |

The Python files missing headers are all of `demo/*.py`, `scripts/*.py`, and
`tests/probes/*.py`. `CONTRIBUTING.md` only explicitly requires SPDX on new Go
source files, but the audit requirement is repo-wide SPDX presence, so this
gate is recorded as FAIL pending an explicit policy decision or headers.

## 5. Release artifacts signed and verifiable — FAIL

- `.goreleaser.yaml` configures SHA-256 checksums, a Cosign signature over
  `checksums.txt`, and SBOM generation. `.github/workflows/release.yml` installs
  Cosign/Syft, runs `make check`, runs the selftest, and invokes GoReleaser on
  `v*` tags.
- There is **no release to verify**: no local/remote tags and 0 GitHub releases.
- `https://github.com/ANIMANxd/sylenix-guard/releases/latest` does not expose a
  real release asset; `/releases` is empty.
- The install endpoints named in the README are absent:
  - `https://github.com/ANIMANxd/homebrew-tap` → **HTTP 404**
  - `https://github.com/ANIMANxd/scoop-bucket` → **HTTP 404**
- Therefore archive/checksum/signature/SBOM verification has never been exercised
  for this project. The configuration is present; the verifiable artifact gate
  is not satisfied.

## 6. README numbers match raw data — PASS

The README launch table matches `results/raw/2026-11-counts.json`:

| README claim | Raw value | Match |
|---|---|---|
| Guarded runs with a canary leak (harness + sweep): 0 / 110 | `combined_guarded: {leaked: 0, runs: 110}` | PASS |
| Guarded sweep including file-channel rescore: 0 / 70 | `sweep.guarded_leaked: [0, 70]` | PASS |
| Unguarded sweep leaked: 48 / 70 | `sweep.direct_leaked: [48, 70]` | PASS |
| Unguarded harness attacks leaked: 10 / 20 | `harness.direct_attack_leaked: [10, 20]` | PASS |
| Guarded harness attacks leaked: 0 / 20 | `harness.guarded_attack_leaked: [0, 20]` | PASS |
| Outside ten-probe set blocked: 20 / 20 | `outside_probes.rows: 20`, `rule_mismatches: 0` | PASS |

The older October numbers in README match `results/2026-11-launch.md`
(56/70, 11/20, 0/110). Every top-of-README measured number has a source path in
the table text and the report link.

**Provenance caveat:** the raw evaluation records build commit `7305895`, while
the audited HEAD is `5a1c520`. The README does not state the measured commit in
the summary table. The numbers are truthful for the recorded evaluation, but
they are not measurements of the current HEAD. This is a documentation
provenance risk, not a raw-data mismatch.

## 7. README and docs claims — FAIL

### Confirmed false or stale claims

1. **README install paths are not currently usable.**
   - README offers Homebrew, Scoop and a latest-release binary.
   - There are no releases/tags; the Homebrew tap and Scoop bucket URLs return
     404. A new developer cannot follow the top of the README successfully
     today.
2. **`docs/ARCHITECTURE.md` has the wrong proxy default.**
   - Doc line 40: `--listen` defaults to `127.0.0.1:8633`.
   - Code: `cmd/sylenix-guard/main.go:992` defaults to `127.0.0.1:8080`;
     README also says 8080.
3. **`docs/ARCHITECTURE.md` says “standard library only”.**
   - Doc line 10.
   - Code imports in-repo packages at
     `cmd/sylenix-guard/main.go:51-52` (`teams/auditevent`,
     `teams/auditshipper`). It is still dependency-free of third-party modules,
     but not standard-library-only.
4. **`docs/ARCHITECTURE.md` line references are stale.**
   - It locates `main()` at line 225; actual `main()` is at line 378 after the
     later feature work. Many other `:NNN` references have shifted similarly.
5. **Governance layout statements are stale.**
   - `AGENTS.md:23` says “No new packages”.
   - `CONTRIBUTING.md:3` says “standard-library-only Go gateway”.
   - The current tree has the `teams/` packages imported by the main binary.
     This is policy/documentation drift, not a runtime defect.
6. **`docs/INSTALL.md` release-artifact descriptions are ahead of reality.**
   - It documents release archives, checksums, Cosign bundles, SBOMs, Homebrew
     and Scoop manifests. None are published at this commit.

### Claims checked and found consistent

- README quick-start commands (`install --yes`, `doctor`) exist and are covered
  by `tests/probes/test_install.py` and `test_doctor.py`.
- README’s security tiers, deny/hard-block behavior, signing and clear-taint
  descriptions match the code and probes.
- README’s “no argument values” and “fail closed” statements match the tests and
  code review.
- README’s measured numbers match the raw data (section 6).
- The new 20-second GIF is present, has no external runtime dependency, and the
  tape/gifrunner can regenerate it with `make gif`; the prompt is explicitly
  labelled as a terminal representation, not a real OS dialog.
- README’s limits section is still present and materially honest; it was not
  removed or softened by the README rewrite.

## 8. Prompt count per active hour — PASS

`python scripts/replay_profile_session.py`:

```text
session: demo/fixtures/normal_session.json
profile: filesystem (npm @modelcontextprotocol/server-filesystem 2.2.0)
calls replayed: 39 over 1.00 active hour(s)
approval prompts needed: 1 (1.00/hour)
hard blocks: 0; errors: 0
budget: < 10/hour -> PASS
```

Target (< 10 prompts/hour) passes. This is a friction metric only; it does not
offset the broken clean-machine install path recorded in the Friction gate.

## 9. TODO/FIXME and open-risk register

A repo-wide text search of tracked non-video files found **no TODO/FIXME/XXX/HACK
markers**:

```text
git grep -n -I -i -E '\b(todo|fixme|xxx|hack)\b' -- . ':!video'
exit 1 (no matches)
```

Open tracked risks (not code TODO markers):

| Risk | Rating | Evidence / impact |
|---|---|---|
| No release/tag or installable artifacts | **High** | 0 tags/releases; tap/bucket 404; README install path fails. Blocks launch. |
| macOS CI red in `team-test` | **High** | CI run 42798765577; `auditshipper`/`policyserver` FAIL; exact test failure unresolved without macOS logs. |
| Docs claim drift (architecture default port, standard-library wording, stale line refs, governance package rule) | **Medium** | Wrong operational default and contributor guidance; can mislead users. |
| Python SPDX headers missing | **Low–Medium** | 24 files; legal/process hygiene, not runtime. |
| AUD-09 oversize no-newline stall / silent EOF | **Medium** | Availability residual, no confidentiality bypass; `docs/AUDIT_2.md`. |
| AUD-08 grandchild process survives | **Low** | Process-cleanup residual; documented in `POC_SPIKE.md`/`AUDIT_1.md`. |
| Release workflow actions use mutable version tags (`@v7`, `@v3`, `@v0`, `~> v2`) rather than commit SHAs | **Low** | Supply-chain hardening; `.github/workflows/release.yml`. |
| Measured results are from commit `7305895`, not HEAD | **Low** | README table does not state the measured commit; source report does. |

## 10. Required action before a GO

1. Publish a release/tag and make the Homebrew/Scoop artifacts exist, then verify
   the checksum signature and archives end to end.
2. Make the macOS `make check` job green and capture the failing test evidence.
3. Correct `docs/ARCHITECTURE.md` (port 8080, actual package layout, refreshed
   line references) and the `AGENTS.md`/`CONTRIBUTING.md` package policy.
4. Decide whether Python files require SPDX; if yes, add headers or explicitly
   narrow the policy.
5. State the measured commit (`7305895`) next to the README launch numbers.
6. Keep AUD-09/AUD-08 declared as residual limits; do not treat them as fixed
   while the current code still exhibits them.
