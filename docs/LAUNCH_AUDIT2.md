# Launch audit 2 — post-fix verification

- **Audit date:** 2026-11-10
- **Previous audit:** `docs/LAUNCH_AUDIT.md`, audited commit `5a1c520`
- **Verified commit:** `c5a438d` (`master`)
- **Method:** re-check every finding in Launch audit 1 against the current tree,
  run the full local gate, inspect the GitHub Actions run, and re-check the
  release/tag/install endpoints. The fixes did not change product Go code.

## Gate verdicts

| Gate | Verdict | Reason |
|---|---:|---|
| Security | **PASS (current tree)** | The macOS matrix failure is fixed and CI is green on Ubuntu, Windows and macOS. The local suite is green. No open policy bypass was found. The release-to-release test comparison remains unverifiable until a tag exists; that is tracked under Release integrity. |
| Friction | **NO-GO** | The source-build path works and the README is now honest, but there is still no release. Homebrew, Scoop and release binaries are unavailable, and both package repositories still return 404. |
| Release integrity | **NO-GO** | No tag, no GitHub release and no signed/downloadable artifacts exist, so the Cosign/SBOM/checksum path is still unexercised. |
| Documentation truth | **PASS** | Every false or stale claim listed in Launch audit 1 section 7 has been corrected. SPDX coverage is complete, actions are pinned, and the measured commit is stated. |
| **Overall launch** | **NO-GO** | Code, CI and documentation are ready. The remaining blocker is the release/install artifact path, not the guard itself. |

---

## 1. Evidence at `c5a438d`

- **Local gate:** `make check` exits **0**, including `spdx-check` and
  `team-test`.
- **CI:** GitHub Actions run
  [`42818111584`](https://github.com/ANIMANxd/sylenix-guard/actions/runs/42818111584)
  completed with all jobs green:

  | Job | Result |
  |---|---:|
  | `make check (ubuntu-latest)` | success |
  | `make check (windows-latest)` | success |
  | `make check (macos-latest)` | success |

- **SPDX:** 15/15 Go files and 24/24 Python files carry
  `SPDX-License-Identifier: Apache-2.0`. `make spdx-check` passes, and a
  temporary headerless Python file makes it fail as intended.
- **Formatting:** `gofmt -l cmd teams demo` prints nothing.
- **Whitespace:** `git diff --check` is clean.
- **Tests:** all suites pass, including 100/100 self-tests in both modes, the
  stdio/HTTP/signing/profile/replay/doctor/clear-taint/stats probes, and
  `go test ./teams/...` for `auditevent`, `auditshipper` and `policyserver`.
- **Product code:** no `.go` files were changed by the documentation/CI/SPDX
  work.

## 2. Launch audit 1 findings

| Audit 1 finding | Status at `c5a438d` | Evidence |
|---|---|---|
| README install paths unusable | **Partially resolved (docs)** | README now labels Homebrew/Scoop and release binaries as available from `v0.1.0`, states there is no release at this commit, and gives a source-build fallback. The install artifacts still do not exist. |
| `docs/ARCHITECTURE.md` wrong proxy default | **Fixed** | Default is `127.0.0.1:8080`, matching the code and README. |
| “standard library only” claim | **Fixed** | Replaced with “no third-party modules” plus the in-repo `teams/` layout. |
| Stale `file:line` references | **Fixed** | All line references were removed or replaced with function/type names. The only remaining `:NNNN` strings are the two `127.0.0.1:8080` port values. |
| Stale governance layout statements | **Fixed** | `AGENTS.md` and `CONTRIBUTING.md` now describe `teams/`, the proxy core, SPDX, and the current test commands. |
| `docs/INSTALL.md` release descriptions ahead of reality | **Fixed** | The document states that artifacts start at `v0.1.0`, that no release exists at this commit, and that the described artifacts are what a release will contain. |
| Python SPDX headers missing | **Fixed** | 24/24 Python files now carry the header; `spdx-check` is part of `make check`. |
| README does not state the measured commit | **Fixed** | The launch table now states “measured at commit `7305895` (Guard `0.1.0`)” and explains that current HEAD contains later work. |
| Mutable action tags in workflows | **Fixed** | Every `uses:` entry in `ci.yml` and `release.yml` is pinned to a full commit SHA with the version kept as a comment. |
| macOS `make check` red in `team-test` | **Fixed and verified** | macOS job is green at `c5a438d`; see section 3. |
| No release/tag or installable artifacts | **Open** | `git tag --list` and `git ls-remote --tags origin` are empty; the GitHub releases API returns 0 releases; `ANIMANxd/homebrew-tap` and `ANIMANxd/scoop-bucket` return 404. |

## 3. macOS `LC_UUID` failure and fix

The original failure was not in the test assertions. `auditshipper` and
`policyserver` are the two team packages that import `net/http`. With cgo
enabled, `go test` linked those test binaries externally, and the newer macOS
SDK produced a Mach-O without `LC_UUID`; dyld aborted before the tests ran.
`auditevent` has no network imports, used Go’s internal linker, and passed.

`team-test` now runs:

```bash
CGO_ENABLED=0 go test ./teams/... -count=1
```

`CGO_ENABLED=0` forces internal linking, and Go’s internal linker emits
`LC_UUID`. This also matches the existing `CGO_ENABLED=0` build and vet
commands, and it propagates to child `go build` calls in the integration test.
The macOS job is green at `c5a438d`.

## 4. Remaining blocker

The only launch blocker left is the release/install path:

1. Create and push the `v0.1.0` tag.
2. Let the release workflow publish the archives, checksums, Cosign bundle and
   SBOMs.
3. Publish the Homebrew tap and Scoop bucket, then run the documented
   clean-machine install commands.
4. Verify the downloaded archive, checksum and Cosign signature end to end.

Until those exist, the Friction and Release integrity gates remain **NO-GO**.
The README now says this instead of implying the paths work today.

## 5. Residual risks carried forward

These are unchanged from Launch audit 1 and are not release blockers by
themselves:

- **AUD-09:** an unterminated oversize line can stall the stream, and EOF
  mid-oversize-line can produce a silent EOF.
- **AUD-08:** SIGTERM kills the direct server process but not descendants.
- **Release reproducibility:** the macOS fix is verified by one green run at
  `c5a438d`; keep the matrix in place so later changes cannot silently regress
  it.
- **Historical record:** `docs/LAUNCH_AUDIT.md` is left unchanged as the
  original audit snapshot. This document records the post-fix state.
