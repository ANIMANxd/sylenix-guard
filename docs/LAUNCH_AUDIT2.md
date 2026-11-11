# Launch audit 2 — post-fix and v0.1.0 release verification

- **Audit date:** 2026-11-11
- **Previous audit:** `docs/LAUNCH_AUDIT.md`, audited commit `5a1c520`
- **Verified code commit:** `c5a438d` (`master`)
- **Release tag:** `v0.1.0` -> `ab52dce`
- **Method:** re-check every finding in Launch audit 1, run the full local gate,
  inspect both the CI and release workflow runs, download and verify the
  published artifacts, and test the install-facing manifests.

## Gate verdicts

| Gate | Verdict | Reason |
|---|---:|---|
| Security | **PASS (current tree)** | CI is green on Ubuntu, Windows and macOS at `c5a438d`. The `v0.1.0` release workflow ran `make check` and the protocol self-test successfully. No open policy bypass was found. |
| Friction | **PASS** | The release exists, the Scoop manifest installs successfully, and the Homebrew formula hashes and URLs match the published checksums. The Homebrew install itself was not executed on this Windows host; see section 3. |
| Release integrity | **PASS** | The tag and release exist. All 10 checksummed archive/SBOM files match. The Cosign bundle verifies against the release workflow identity. The Windows release binary reports `0.1.0`. |
| Documentation truth | **PASS** | The repository claims from Launch audit 1 are corrected, and the README/INSTALL release wording now matches the published `v0.1.0` artifacts and package manifests. |
| **Overall launch** | **GO** | Code, CI, documentation, release artifacts, signatures and both package manifests pass. The only verification gap is that Homebrew was not run on macOS in this environment. |

---

## 1. Evidence at `c5a438d` and `v0.1.0`

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

- **Release workflow:** run
  [`42856376019`](https://github.com/ANIMANxd/sylenix-guard/actions/runs/42856376019)
  completed successfully. Both the `check before release` job (`make check`
  and an explicit protocol self-test) and the `build and publish release` job
  succeeded.
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

## 2. v0.1.0 release verification

The tag and release are real:

- `git tag --list` contains `v0.1.0`; the annotated tag object is
  `d8fecf4`, peeling to commit `ab52dce`.
- The GitHub release
  [`v0.1.0`](https://github.com/ANIMANxd/sylenix-guard/releases/tag/v0.1.0)
  is published, not a draft and not a prerelease. It was published on
  2026-11-10 at 16:39:51 UTC.
- The release contains **14 assets**: five platform archives, five SBOMs,
  `checksums.txt`, `checksums.txt.sigstore.json`, `sylenix-guard.rb` and
  `sylenix-guard.json`.

Artifact verification:

- All **10/10** archive and SBOM hashes in `checksums.txt` match the downloaded
  files.
- The Cosign bundle verifies:

  ```text
  cosign verify-blob
    --bundle checksums.txt.sigstore.json
    --certificate-identity https://github.com/ANIMANxd/sylenix-guard/.github/workflows/release.yml@refs/tags/v0.1.0
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
    checksums.txt
  ```

  Result: `Verified OK` (Cosign v3.1.4).
- The Windows archive extracts cleanly; `sylenix-guard.exe doctor` prints
  `Sylenix Guard doctor 0.1.0` and exits 0.

## 3. Package-manager verification

The placeholder hashes were fixed in both external repositories:

- `homebrew-tap` commit `660ff0a`, "Fix sha256 checksum formatting in
  sylenix-guard formula"
- `scoop-bucket` commit `5da4eeeb`, "Fix hash format in sylenix-guard.json"

The live formula now contains plain digests that match the release checksums:

```ruby
sha256 "3239a24bca7ac8bc6d0ecdb12bbc6ade1a22e05368d4be48900a79060966abdf"
sha256 "6bfcc0888f5df7a531c5da114f1070b7f0c0a785f702f3a7699b19a376b1385d"
sha256 "1298e58e3f6ea6ef7655f611f9c24bf815c83c3028e2dc1d34ad8f5c6312f991"
sha256 "39800c9d288579f941bd6afdcf0e9ba8de306a171f4e27a28b3b7534f9ee30d3"
```

The live Scoop manifest contains the matching digest:

```json
"hash": "e619d016a7924192f1d9471835a4627b240a9f946a6a151da70957ce2d016428"
```

Scoop was exercised end to end on Windows:

```text
scoop update
scoop download sylenix/sylenix-guard
  Checking hash of sylenix-guard_0.1.0_windows_amd64.zip... OK.
scoop install sylenix/sylenix-guard
  Checking hash of sylenix-guard_0.1.0_windows_amd64.zip... OK.
  'sylenix-guard' (0.1.0) was installed successfully!
sylenix-guard doctor
  Sylenix Guard doctor 0.1.0
  No findings.
```

Homebrew was not executed because this audit ran on Windows and Homebrew is
not installed here. Its formula was checked statically: all four platform URLs
point at the `v0.1.0` release assets, and all four SHA-256 values match
`checksums.txt`.

## 4. Launch audit 1 findings

| Audit 1 finding | Status at `v0.1.0` | Evidence |
|---|---|---|
| README install paths unusable | **Fixed** | The release exists, Scoop installs successfully, the Homebrew formula matches the release checksums, and the source-build fallback works. |
| `docs/ARCHITECTURE.md` wrong proxy default | **Fixed** | Default is `127.0.0.1:8080`, matching the code and README. |
| “standard library only” claim | **Fixed** | Replaced with “no third-party modules” plus the in-repo `teams/` layout. |
| Stale `file:line` references | **Fixed** | All line references were removed or replaced with function/type names. The only remaining `:NNNN` strings are the two `127.0.0.1:8080` port values. |
| Stale governance layout statements | **Fixed** | `AGENTS.md` and `CONTRIBUTING.md` now describe `teams/`, the proxy core, SPDX, and the current test commands. |
| `docs/INSTALL.md` release descriptions ahead of reality | **Fixed** | The document now matches the published `v0.1.0` release. |
| Python SPDX headers missing | **Fixed** | 24/24 Python files now carry the header; `spdx-check` is part of `make check`. |
| README does not state the measured commit | **Fixed** | The launch table states “measured at commit `7305895` (Guard `0.1.0`)” and explains that current HEAD contains later work. |
| Mutable action tags in workflows | **Fixed** | Every `uses:` entry in `ci.yml` and `release.yml` is pinned to a full commit SHA with the version kept as a comment. |
| macOS `make check` red in `team-test` | **Fixed and verified** | macOS job is green at `c5a438d`; see section 5. |
| No release/tag or installable artifacts | **Resolved** | Tag, release, archives, checksums, Cosign bundle and SBOMs exist and verify. Both package manifests now carry valid hashes; Scoop install was executed. |

## 5. macOS `LC_UUID` failure and fix

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

## 6. Launch status

No launch blockers remain:

- The tag, release and signed artifacts are published and verified.
- Both package manifests now carry valid hashes.
- Scoop was installed and run successfully on Windows.
- The Homebrew formula hashes and URLs match the published checksums.
- README and `docs/INSTALL.md` now describe the published release rather than a
  future one.

The only outstanding verification gap is that `brew install` was not executed
on macOS in this environment. Run it once before the next release; it does not
block the current launch because the formula and hashes are statically correct.

## 7. Residual risks carried forward

These are unchanged from Launch audit 1 and are not launch blockers by
themselves:

- **AUD-09:** an unterminated oversize line can stall the stream, and EOF
  mid-oversize-line can produce a silent EOF.
- **AUD-08:** SIGTERM kills the direct server process but not descendants.
- **Homebrew execution gap:** the formula was checked statically, not installed
  on macOS. Add a macOS install check to the next release.
- **Release reproducibility:** the macOS fix is verified by one green run at
  `c5a438d`; keep the matrix in place so later changes cannot silently regress
  it.
- **Historical record:** `docs/LAUNCH_AUDIT.md` is left unchanged as the
  original audit snapshot. This document records the post-fix and release
  state.
