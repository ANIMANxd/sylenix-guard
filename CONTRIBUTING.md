# Contributing

Sylenix Guard is a small Go gateway with no third-party modules. Keep changes
focused and explain any behaviour change in `CHANGELOG.md` and the relevant
limitations in `POC_SPIKE.md`.

## Build

```bash
CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard
```

On Windows, also build the `.exe`, because MCP hosts resolve commands through
`PATHEXT` and can otherwise run a stale binary:

```powershell
$env:CGO_ENABLED='0'; go build -o bin/sylenix-guard.exe ./cmd/sylenix-guard
```

The proxy core stays in `cmd/sylenix-guard/main.go`. The paid-tier policy and
audit service lives under `teams/` and may be imported by the proxy for the
optional team-policy and audit-shipping paths. Do not add third-party
dependencies without discussing them first.

## Checks

Run the full gate before opening a pull request:

```bash
make check
```

`make check` runs gofmt, the SPDX check, `go vet`, the protocol self-test, the
stdio, Streamable HTTP and signing probe suites, the profile/replay/doctor/
clear-taint/stats probes, the audit summarizer fixture and the `teams/` Go tests.
On Windows, `make check` needs a POSIX shell (Git Bash or WSL), as described in
`README.md`.

You can also run the main pieces directly:

```bash
gofmt -l cmd teams demo
CGO_ENABLED=0 go vet ./...
python demo/selftest.py
python tests/probes/test_http_proxy.py
python tests/probes/test_signing.py
python tests/probes/test_scratch_grant_bypass.py
python tests/probes/test_protected_targets.py
CGO_ENABLED=0 go test ./teams/...
```

The scripted harness is a wiring check only; never quote its numbers as
evidence:

```bash
python demo/harness.py --agent scripted --runs 3
```

## Tests and probes are never weakened

Do not delete, skip, loosen or rewrite a test, probe or self-test check to make
a change pass. If a test looks wrong, stop and explain why in the pull request;
fix the cause instead. Every security fix needs a regression test that fails
before the fix and passes after it.

Fail closed. When parsing, classification or configuration is uncertain, block
and explain. Never log argument values, secrets, tokens or tool output; the
audit log records tool names, argument key names, decisions and rule names only.

## Pull request checklist

- [ ] The change is focused and does not include unrelated refactors.
- [ ] `gofmt -l cmd teams demo` prints nothing.
- [ ] `CGO_ENABLED=0 go vet ./...` passes.
- [ ] `make check` passes, including `spdx-check` and
      `CGO_ENABLED=0 go test ./teams/...`.
- [ ] `python demo/selftest.py` passes.
- [ ] New security behaviour has a regression test that fails before the fix.
- [ ] No existing test, probe or self-test check was weakened or skipped.
- [ ] No argument values, secrets, tokens or tool output are logged.
- [ ] No new third-party dependency was added without agreement.
- [ ] `CHANGELOG.md` and the relevant limitations are updated.
- [ ] New `.go` and `.py` source files carry
      `// SPDX-License-Identifier: Apache-2.0` or
      `# SPDX-License-Identifier: Apache-2.0` respectively.
- [ ] Suspected bypasses are reported privately as described in `SECURITY.md`,
      not in a public issue or pull request.

## License

Contributions are accepted under the Apache License 2.0. See `LICENSE`.
