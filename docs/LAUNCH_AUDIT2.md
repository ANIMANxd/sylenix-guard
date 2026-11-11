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
| Friction | **NO-GO** | The release exists and the archives work, but the live Homebrew formula and Scoop manifest contain literal `<sha256:...>` placeholder hashes. Both package-manager installs will fail checksum validation. |
| Release integrity | **PASS** | The tag and release exist. All 10 checksummed archive/SBOM files match. The Cosign bundle verifies against the release workflow identity. The Windows release binary reports `0.1.0`. |
| Documentation truth | **PARTIAL** | The repository claims from Launch audit 1 are corrected, but the README's Homebrew/Scoop commands are not currently usable because the external manifests are invalid. |
| **Overall launch** | **NO-GO** | Code, CI, release artifacts and signatures are ready. The only blocker is the two package-manager manifests. |

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

## 3. Homebrew and Scoop blocker

The repositories now exist and contain the expected files:

- `ANIMANxd/homebrew-tap`, `Formula/sylenix-guard.rb`, version `0.1.0`
- `ANIMANxd/scoop-bucket`, `bucket/sylenix-guard.json`, version `0.1.0`

However, the live hashes are placeholders, not digests:

```ruby
sha256 "<sha256:3239a24bca7ac8bc6d0ecdb12bbc6ade1a22e05368d4be48900a79060966abdf>"
```

```json
"hash": "<sha256:e619d016a7924192f1d9471835a4627b240a9f946a6a151da70957ce2d016428>"
```

The angle brackets and `sha256:` prefix make these invalid checksum values.
`brew install ANIMANxd/tap/sylenix-guard` and
`scoop install sylenix/sylenix-guard` will therefore fail checksum validation.

The copies attached to the GitHub release are correct:

- `sylenix-guard.rb` has the plain `3239...`, `6bfc...`, `1298...` and
  `3980...` digests.
- `sylenix-guard.json` has the plain `e619...` digest.

The fix is to replace the live tap/bucket files with the release copies, or
strip the `<sha256:` prefix and `>` suffix from the existing values, then run
both documented installs on macOS and Windows.

## 4. Launch audit 1 findings

| Audit 1 finding | Status at `v0.1.0` | Evidence |
|---|---|---|
| README install paths unusable | **Partially resolved** | The release now exists and the source-build fallback works. Homebrew/Scoop are still broken by the placeholder hashes in section 3. |
| `docs/ARCHITECTURE.md` wrong proxy default | **Fixed** | Default is `127.0.0.1:8080`, matching the code and README. |
| “standard library only” claim | **Fixed** | Replaced with “no third-party modules” plus the in-repo `teams/` layout. |
| Stale `file:line` references | **Fixed** | All line references were removed or replaced with function/type names. The only remaining `:NNNN` strings are the two `127.0.0.1:8080` port values. |
| Stale governance layout statements | **Fixed** | `AGENTS.md` and `CONTRIBUTING.md` now describe `teams/`, the proxy core, SPDX, and the current test commands. |
| `docs/INSTALL.md` release descriptions ahead of reality | **Fixed** | The document now matches the published `v0.1.0` release. |
| Python SPDX headers missing | **Fixed** | 24/24 Python files now carry the header; `spdx-check` is part of `make check`. |
| README does not state the measured commit | **Fixed** | The launch table states “measured at commit `7305895` (Guard `0.1.0`)” and explains that current HEAD contains later work. |
| Mutable action tags in workflows | **Fixed** | Every `uses:` entry in `ci.yml` and `release.yml` is pinned to a full commit SHA with the version kept as a comment. |
| macOS `make check` red in `team-test` | **Fixed and verified** | macOS job is green at `c5a438d`; see section 5. |
| No release/tag or installable artifacts | **Resolved (release), manifests open** | Tag, release, archives, checksums, Cosign bundle and SBOMs exist and verify. The live Homebrew/Scoop manifests are invalid. |

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

## 6. Remaining blocker

Only the package-manager manifests remain:

1. Replace the Homebrew formula hashes with the correct digests, or copy the
   valid `sylenix-guard.rb` from the release assets into
   `homebrew-tap/Formula/sylenix-guard.rb`.
2. Replace the Scoop manifest hash with the correct digest, or copy the valid
   `sylenix-guard.json` from the release assets into
   `scoop-bucket/bucket/sylenix-guard.json`.
3. Run `brew install ANIMANxd/tap/sylenix-guard` on macOS and
   `scoop install sylenix/sylenix-guard` on Windows.
4. Re-check the Friction and Documentation truth gates.

Until those pass, the overall launch verdict remains **NO-GO**. The release
artifacts themselves are valid and signed.

## 7. Residual risks carried forward

These are unchanged from Launch audit 1 and are not package-manifest blockers:

- **AUD-09:** an unterminated oversize line can stall the stream, and EOF
  mid-oversize-line can produce a silent EOF.
- **AUD-08:** SIGTERM kills the direct server process but not descendants.
- **Release reproducibility:** the macOS fix is verified by one green run at
  `c5a438d`; keep the matrix in place so later changes cannot silently regress
  it.
- **Historical record:** `docs/LAUNCH_AUDIT.md` is left unchanged as the
  original audit snapshot. This document records the post-fix and release
  state.
