    # AGENTS.md — Sylenix Guard (post-POC)

Sylenix Guard is a gateway that sits between an AI agent host and one MCP server, over stdio or Streamable HTTP. The 72-hour proof-of-concept phase is complete and evaluated; `POC_SPIKE.md` is the historical record plus the post-POC scope note. This repository contains Sylenix Guard only.

## Where things are

- `POC_SPIKE.md`: spike record, plan and decision gates, plus the post-POC scope note. It governs what you may build right now.
- `docs/SPEC_FULL.md`: the long-term product spec. Read its section 2 (axioms) and section 3 (threat model) for intent. Do not implement anything from it that `POC_SPIKE.md` puts out of scope.
- `cmd/sylenix-guard/main.go`: the proxy core, in one file. It uses the standard library plus the optional in-repo `teams/` packages.
- `teams/`: the paid-tier policy service, audit shipper, collector, dashboard and evidence exports. In-repo only; no third-party modules.
- `demo/`: real-agent harness, demo MCP server, protocol tests and the terminal GIF runner.
- `scripts/`: helper scripts.

## Commands

```bash
make check             # gofmt, SPDX check, go vet, protocol/proxy/team tests; must stay green
make build             # builds bin/sylenix-guard and bin/sylenix-teams
make gif               # regenerates demo/quickstart.gif with vhs
make harness-scripted  # wiring check only; never quote its numbers
```

## Rules

1. Keep the proxy core in `cmd/sylenix-guard/main.go`. Paid-tier policy/audit code belongs under `teams/` and may be imported by the proxy; no third-party dependencies.
2. Do not add features beyond `POC_SPIKE.md` section 2 and its post-POC extension. If something seems needed, say so instead of building it.
3. Never weaken or delete a test, or loosen a block, to make something pass. Fix the cause.
4. The guard must never log argument values, secrets or tool output. The harness may record them in per-run transcripts because they are test data.
5. Unknown means most restrictive: unmapped tools, unparseable frames, anything the guard cannot classify.
6. Do not claim a behavior the code does not have. Update the limitations in `POC_SPIKE.md` section 7 instead.
7. Never reference other Sylenix Labs products in this repository.
