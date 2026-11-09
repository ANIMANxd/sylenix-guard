# AGENTS.md — Sylenix Guard

**Product:** Sylenix Guard, a capability-bound agent gateway and runtime firewall
**Organization:** Sylenix Labs LLP (Bengaluru, Karnataka, India)
**Language:** Go 1.25+. The main binary is pure Go (`CGO_ENABLED=0`). Cgo is allowed only in `advisor-worker` (ONNX Runtime) and the per-OS `sylenix-approve` helper.
**Platforms:** macOS (arm64, x86_64), Linux (x86_64, arm64), Windows (x86_64)
**License:** Apache 2.0
**Status:** Specification v0.2, revised 10 Oct 2026 after design review

---

## 0. Working in this repo (read this first)

### Commands

These are the expected Makefile targets. If one is missing, add it to the Makefile instead of inventing an ad-hoc command.

```bash
make build                   # build all binaries for the host platform
make test                    # hermetic unit tests (no network)
make lint                    # go vet + staticcheck
make fuzz                    # fuzz targets: JSON-RPC parser, path verifier, SQL verifier, sanitizer
make test-security-ablation  # attack suites with layer-by-layer ablation
make bench                   # reproducible benchmark run (ASR + utility + latency)
```

### Rules for every engineer and coding agent

1. **Never bypass or weaken a layer to make a test pass.** If a test fails, fix the capability boundary, not the policy.
2. **Models only tighten.** Advisor output reaches a decision only through `protocol.Tighten()`. Do not add any other path from model output to a decision.
3. **Unknown means most restrictive.** Unmapped tools, unparseable frames, unsupported SQL dialects, missing sandbox capability: all default to the strictest handling.
4. **No external network** in the core enforcement loop or in tests under `internal/`.
5. **Every rule ships with fixtures**: at least one input that must pass and one adversarial input that must be blocked, in `test/fixtures/`.
6. **Never log raw arguments, secrets, or PII.** The ledger stores keyed hashes and schema paths only.
7. **Do not overclaim.** If you change what the gateway can see or enforce, update section 3 in the same change.
8. **Tie every child process to a context** (`os/exec.CommandContext`) and kill the whole process group on exit.

---

## 1. What Sylenix Guard is, and what it is not

Sylenix Guard sits in-line between an agent runtime (Cursor, Claude Desktop, LangGraph, custom worker pools) and the tools it calls: MCP servers, databases, network endpoints, and shell execution. It enforces deterministic capability rules, tracks where data came from, requires out-of-band human approval for risky actions, keeps real credentials away from the model, and writes tamper-evident evidence of every decision.

It runs in two topologies:

- **Mode 1, stdio interceptor:** sits between a host application and a spawned child MCP server, mediating the stdio JSON-RPC stream.
- **Mode 2, Layer-7 reverse proxy:** mediates HTTP/mTLS, SSE, multi round-trip requests, and provider-native `/v1/chat/completions` and `/v1/messages` tool calls. The current build implements the Streamable HTTP MCP part (one remote server, MCP 2025-11-25, with 2026-07-28 tolerance); provider-native endpoints, multi-server routing, and credential brokering remain future work.

**What it is not:** it does not see anything that does not pass through it (see section 3.4), and it does not secure the model's own replies to the user. It reduces and contains risk; it does not make an agent "safe" in general.

---

## 2. Axioms

These are non-negotiable and every layer must uphold them.

1. **Asymmetric authority.** Detection can only add friction; it can never grant permission. Authority comes from deterministic capabilities and cryptographic grants. Neural or heuristic components may escalate to approval or block. They may not loosen a decision. This is enforced structurally: the advisor's output type can only be consumed by `Tighten()`, and a property test proves `Tighten(base, x) >= base` for all inputs.

2. **Taint latching with persistent provenance.** Once untrusted data enters a mediated session, the session is `Tainted` for the rest of its life. The latch never clears automatically. Taint also follows artifacts: anything a tainted session writes carries a provenance label, and a later session that reads a labeled artifact becomes tainted.

3. **Credential oblivion.** The model never sees, stores, or transmits raw secrets. It handles only opaque capability handles. Real credentials are substituted at the gateway boundary at dispatch time, and only into the argument field and destination that the handle is bound to.

4. **Fail closed.** Any pipeline error, unparseable frame, broken pipe, buffer overrun, or internal timeout results in `HARD_BLOCK` for every tool above read-only. One refinement: if only the Risk Advisor is unavailable or late, the call is escalated to approval rather than blocked, because escalation is itself a tightening and no action proceeds without authority.

5. **Physical separation of approval.** Human authorization happens on an out-of-band channel that the agent host cannot render into, script, or observe. Approval prompts never appear inside the agent's own UI or chat stream.

6. **Declared coverage.** The gateway makes guarantees only about traffic it actually sees. Channels that bypass it must be declared in the host profile, and undeclared coverage is treated as partial (section 3.4).

---

## 3. Threat model and trust boundary

### 3.1 Assets

- Credentials and secrets reachable by tools.
- Integrity of state-mutating actions: file writes, database mutations, process execution, network egress.
- Confidentiality of data reachable through tools.
- Integrity of the audit evidence.

### 3.2 Adversaries in scope

- **A1. Indirect prompt injection** in any tool output the gateway sees (web pages, tickets, files, database rows).
- **A2. Malicious or compromised MCP server**: tool poisoning, tool shadowing, rug-pull schema changes, hostile outputs.
- **A3. A steered agent.** After taint, assume the model is fully attacker-controlled.
- **A4. Exfiltration** through tool arguments, URLs, markdown links and images, and other covert channels over allowed egress.
- **A5. Zero-day in a downstream MCP server**, contained by the sandbox.

### 3.3 Out of scope

- A compromised host OS or kernel, or root on the user's machine.
- An attacker who controls the approving user's biometric or approval device.
- Supply-chain compromise of Guard itself or of model weights. Releases are signed, but this is not a guarantee.
- Anything that never crosses the gateway (section 3.4).
- Covert channels in the model's own replies rendered directly in the host chat UI.
- Timing and other side channels.

### 3.4 Coverage and host profiles

Guard sees only what is routed through it. Host-native capabilities (built-in file read, web fetch, search, attachments, pasted context, host memory) usually bypass it, which means taint tracking is blind to them.

Configure `host_profile` in the immutable config:

| Profile | Meaning | Session start state |
|---|---|---|
| `mediated_only` | All ingress and egress for the agent goes through Guard (the runtime is configured with only Guard-proxied tools). | `Clean` |
| `partial` | Unmediated ingress channels exist. This is the default for IDE hosts and any unknown host. | `Tainted` |

The active profile and `coverage: full|partial` are recorded in every ledger record and shown by `sylenix-ctl status`. Documentation and marketing must not claim guarantees beyond the active coverage.

### 3.5 Assumptions

- The OS keychain, TPM, or Secure Enclave is trustworthy.
- The approval device is uncompromised.
- Policy files and the manifest pin file are signed, loaded at startup, and immutable at runtime.

---

## 4. Pipeline

Layers 2 to 4 produce facts. The policy engine (`pkg/policy`, Cedar) turns those facts into a base decision. Layer 5 may only tighten it.

```
REQUEST PATH (agent -> tool)

 Host agent / IDE / orchestrator
        |  JSON-RPC tools/call, or provider-native tool_calls
        v
 [0 Manifest Guard]      pinned schema hash, shadowing, hidden unicode
        v
 [2 Effect Classifier]   effect type; unmapped tool => EffectUnclassified
        v
 [3 Flow Controller]     taint + confidentiality latches, provenance lookup
        v
 [4 Argument Verifier]   paths, SQL AST, egress allowlist (early filter)
        v
 [P Policy Engine]       Cedar; produces the base decision
        v
 [5 Risk Advisor]        ambiguous band only; Tighten() only
        v
   ALLOW ---------------------------------------------+
   REQUIRE_APPROVAL --> [6 Approval Broker] -- grant --+
   HARD_BLOCK --> JSON-RPC error back to host          |
                                                       v
 [7 Credential Broker]   swap handles for secrets at the wire
        v
 [8 Sandbox Runner]      enforcement: OS isolation of the MCP server
        v
 Downstream tool / MCP server


RESPONSE PATH (tool -> agent)

 Downstream result
        v
 [1 Ingress Sanitizer]   strip, neutralize, datamark; label Untrusted
        v
 [3 Flow Controller]     ingest: set latches, record origins
        v
 Host agent

 Every decision on both paths is appended to [9 Evidence Ledger] (async).
```

---

## 5. Repository layout

```
sylenix-guard/
├── cmd/
│   ├── sylenix-guard/      # main binary: stdio shim and daemon (pure Go)
│   ├── sylenix-ctl/        # admin CLI: status, policy, audit, grants, doctor
│   ├── sylenix-approve/    # per-OS approval UI helper (native APIs)
│   └── advisor-worker/     # isolated Cgo binary running the Laya ONNX model
├── internal/
│   ├── manifest/           # Layer 0
│   ├── sanitizer/          # Layer 1
│   ├── classifier/         # Layer 2
│   ├── flow/               # Layer 3: lattices, latches, taint tracker
│   ├── provenance/         # persistent artifact labels
│   ├── verifier/           # Layer 4
│   ├── advisor/            # Layer 5: IPC client to advisor-worker
│   ├── approval/           # Layer 6
│   ├── credential/         # Layer 7
│   ├── sandbox/            # Layer 8
│   ├── ledger/             # Layer 9
│   ├── proxy/              # stdio multiplexer and L7 HTTP transport
│   └── config/             # immutable config parsing and validation
├── pkg/
│   ├── protocol/           # JSON-RPC types, Decision, Tighten()
│   ├── crypto/             # canonical JSON (RFC 8785), Merkle, key interfaces
│   └── policy/             # Cedar policy evaluation (cedar-go)
├── models/
│   ├── laya-int8.onnx
│   └── laya-int8.onnx.sha256
├── test/
│   ├── fixtures/           # pass/block vectors, poisoned schemas, attack files
│   ├── benchmarks/         # InjecAgent and AgentDojo runners, thresholds.yaml
│   ├── fuzz/
│   └── e2e/                # process-shim integration tests
├── scripts/
│   └── build.sh            # per-target builds (see section 8.3)
├── Makefile
├── LICENSE                 # Apache 2.0
├── NOTICE                  # Sylenix Labs attribution and trademark notice
└── README.md
```

---

## 6. Layer specifications

### Layer 0: Manifest Guard (`internal/manifest`)

**Objective:** prevent tool poisoning, shadowing, and schema mutation after approval.

- Intercept `tools/list` during initialization.
- Normalize each tool definition (name, description, input schema, annotations) to canonical JSON per RFC 8785 and compute `SchemaHash = SHA256(CanonicalJSON(ToolManifest))`. Use a vetted JCS library; hand-rolled number formatting will get this wrong.
- Compare against pins in `~/.sylenix/manifest_pins.json`. The pin file is signed with the local gateway key and verified on load; an unsigned or modified pin file is a startup error.
- On mismatch or unpinned tool: quarantine the tool, halt the call, and raise an approval challenge (Layer 6).
- Reject definitions containing bidirectional overrides (`U+202E` and friends), zero-width characters (`U+200B` and friends), or descriptions over 2,048 characters.
- Detect shadowing: a tool whose name collides with or closely resembles a pinned tool from a different server is quarantined.

### Layer 1: Ingress Sanitizer (`internal/sanitizer`)

**Objective:** neutralize passive injection vectors and covert channels in tool results before they reach the model. Runs on the response path.

- Strip ANSI escape sequences, terminal control characters, and Unicode tag characters (`U+E0000` to `U+E007F`).
- Neutralize markdown exfiltration patterns (`![img](https://...)`, `[link](https://...)`) when they carry variable or session-derived tokens.
- Datamark every result and label it `Untrusted`:

```xml
<untrusted_tool_result origin="jira-mcp" integrity="untrusted">
... sanitized payload ...
</untrusted_tool_result>
```

- Sanitizing and datamarking are friction. They are never treated as a reason to downgrade taint.

### Layer 2: Effect Classifier (`internal/classifier`)

**Objective:** map every requested action to a fixed risk taxonomy.

```go
type EffectType uint8

const (
    EffectReadOnly       EffectType = iota // get_time, calc: no side effects
    EffectReadSecret                       // read_env, read_keychain, fetch_private_key
    EffectWriteLocal                       // write_file, edit_buffer, make_dir
    EffectDatabaseMutate                   // UPDATE, DELETE, DROP, INSERT, ALTER
    EffectSystemExec                       // bash, sh, cmd.exe, spawn_process
    EffectNetworkEgress                    // http_post, send_email, webhook_dispatch
    EffectUnclassified                     // unmapped or mismatched tool; treated as every sink class at once
)
```

- The mapping lives in signed static policy files and is checked against tool signatures.
- **A tool with no mapping is `EffectUnclassified`**, never `EffectReadOnly`.
- A "read" tool that receives arbitrary shell strings, SQL, or URLs is a structural violation and is reclassified as `EffectUnclassified`.

### Layer 3: Flow Controller (`internal/flow`, `internal/provenance`)

**Objective:** deterministic information-flow control.

**Lattices**

```
Integrity:        Trusted  <  Untrusted     (join of the two is Untrusted)
Confidentiality:  Public   <  Secret
```

Data carries these labels. A session carries two latches: `TaintLatched` (any `Untrusted` data entered the context) and `ConfidentialityLatched` (any `Secret` data entered the context).

`ConfidentialityLatched` is set by: results of `EffectReadSecret` tools, tools or paths labeled `Secret` in policy, any vault handle resolution, and any canary access.

**Rules**

- **IF-1 (integrity).** If `TaintLatched`, then `EffectWriteLocal`, `EffectDatabaseMutate`, `EffectSystemExec`, `EffectNetworkEgress`, and `EffectUnclassified` all require an unexpired grant bound to the action hash (or a covering scoped grant).
- **CF-1 (confidentiality).** If `ConfidentialityLatched`, then `EffectNetworkEgress` requires a grant, and egress to a destination outside the allowlist is `HARD_BLOCK`. No grant overrides that; changing the allowlist is a policy change.
- **TF-1 (trifecta).** If `TaintLatched` and `ConfidentialityLatched` and the call is `EffectNetworkEgress`, the minimum decision is `REQUIRE_APPROVAL`, and the approval prompt must display the trifecta flag.

**Exact-value tracking is advisory only.** Untrusted substrings are normalized (URL, Base64, hex decoding) into a thread-safe Bloom filter and Aho-Corasick automaton. A match of 16 or more characters sets `TaintPresent` on the call, which can only tighten. It is trivially evaded by paraphrase or re-encoding by the model, so it never loosens a decision and never clears a latch.

**Persistent provenance.** When a tainted session writes a file or record, `internal/provenance` stores a label keyed by canonical path and content hash. Reading a labeled artifact re-taints the reading session. Labels are cleared only by a human via `sylenix-ctl`.

**Making this usable (approval fatigue is a security problem):**

- Admins can mark specific origins `Trusted` in signed policy (for example a vetted internal knowledge server). Never by content, only by origin.
- Standing scoped grants: scoped to tool plus path subtree or host, maximum 30 minutes, revocable via `sylenix-ctl`.
- Per-session escalation budget (config). When exceeded, the session enters `review_required`: all sinks hard-block until an admin resets it.
- Approvals per session is a tracked metric (section 9).

### Layer 4: Argument Verifier (`internal/verifier`)

**Objective:** enforce boundaries on structured parameters. **This layer is an early filter. Layer 8 is the enforcement**, because checks here are subject to time-of-check/time-of-use races.

- **Filesystem:** `filepath.Clean`, `filepath.EvalSymlinks`, confinement to the declared workspace root, no `..` traversal. Where available, open with `openat2(RESOLVE_BENEATH)` or `O_NOFOLLOW`.
- **SQL:** deterministic AST parsing (for PostgreSQL, `pganalyze/pg_query_go`). No multi-statement execution; read-only tools may contain only `SELECT` with no mutating CTEs. The parser is dialect-specific. **An unsupported dialect makes the tool `EffectUnclassified`.**
- **Network:** FQDN and CIDR allowlists. Reject loopback, RFC 1918, the whole link-local range (`169.254.0.0/16`, including the cloud metadata endpoint), and the IPv6 equivalents (`::1`, `fc00::/7`, `fe80::/10`). Resolve DNS once and pin the resolved IP to the connection to defeat DNS rebinding.

### Policy Engine (`pkg/policy`)

- Cedar, via `cedar-go`. OPA is not used.
- Inputs are the facts from layers 2 to 4 (effect, latches, flags, verifier results, origin trust). Output is the base `Decision`.
- Policy bundles are signed and loaded at startup.

### Layer 5: Risk Advisor (`internal/advisor`, `cmd/advisor-worker`)

**Objective:** a cheap, non-autoregressive second opinion on ambiguous calls. It tightens; it never loosens.

- **Isolation:** separate OS process, local IPC only.
  - Linux: Unix socket at `$XDG_RUNTIME_DIR/sylenix/advisor.sock`, directory mode `0700`.
  - macOS: Unix socket in the per-user temp directory, mode `0700`.
  - Windows: named pipe `\\.\pipe\sylenix-advisor-<user-sid>` with a restrictive ACL.
  - On every connection verify the peer (`SO_PEERCRED`, `LOCAL_PEERCRED`, or `GetNamedPipeClientProcessId`). Never use a fixed path in `/tmp`.
- **Model:** quantized `laya-int8.onnx` via the ONNX Runtime C API. No token generation. Model size (ModernBERT-base or large) is chosen by measurement on the reference hardware (section 8), not by assumption.
- **Input:** structured metadata only: tool name, effect type, parameter keys, a length-bounded tainted-span snippet. Never the conversation history. The snippet is attacker-controlled text, so treat the advisor as an attack target in its own right.
- **Output:**
  - `Noul`: calibrated `P(adversarial_injection)` in `[0.0, 1.0]`.
  - `Choice`: `BENIGN_OPERATIONAL | DRIFT_AMBIGUOUS | HOSTILE_EXPLOITATION`.
- **Thresholds (config defaults, calibrated on a held-out validation set):**
  - `P < 0.40`: no change to the base decision.
  - `P >= 0.40`: escalate to approval.
  - `P >= 0.85`: `HARD_BLOCK`.
- **Unavailable, timed out, or malformed response:** escalate to approval for any call in the ambiguous band. Do not treat silence as clearance.
- Because the advisor can be induced to escalate, a flood of escalations is a denial-of-service and approval-fatigue vector. The per-session escalation budget from Layer 3 applies to advisor-triggered escalations too.

### Layer 6: Approval Broker (`internal/approval`, `cmd/sylenix-approve`)

**Objective:** capture human authorization without letting the agent host spoof or observe it.

- Hold the pending request in memory and compute
  `ActionHash = SHA256(ToolName || CanonicalJSON(Args) || SessionID)`.
- **Channels** (`approval.channel` in config):
  - `os_biometric`: local interactive use. macOS via LocalAuthentication (Touch ID), Windows via Windows Hello (UserConsentVerifier), Linux via polkit/D-Bus.
  - `webauthn_remote`: headless and CI use. A signed approval request goes to a second, separate device the approver controls. The relay protocol is an open decision (section 12).
  - `admin_preissued`: an authenticated admin pre-issues scoped grants for unattended pipelines.
  - If no configured channel is available, the answer is **deny**.
- **What the human sees is derived from the same canonical arguments that were hashed**, never from an agent-supplied description. Control characters and confusable Unicode are rendered visibly. If the action cannot be shown faithfully (for example oversized arguments), it cannot be approved.
- **Grants:**

```go
type CapabilityGrant struct {
    ActionHash [32]byte
    SessionID  string
    Nonce      [16]byte  // replay protection; consumed nonces are persisted
    SingleUse  bool
    Scope      *GrantScope // nil for single-action grants; set for standing grants
    GrantedAt  time.Time
    ExpiresAt  time.Time
    Signature  []byte    // signed by the gateway key
}
```

- Single-action grants expire after 60 seconds. Standing scoped grants last at most 30 minutes and are revocable. Timeout or dismissal is a denial (`-32002`).

### Layer 7: Credential Broker (`internal/credential`)

**Objective:** keep real secrets out of the model context entirely.

- Secrets live in `~/.sylenix/vault.db`, encrypted with AES-256-GCM under a master key held in the OS keychain.
- The agent sees opaque handles such as `$SYLENIX_HANDLE_POSTGRES_PROD`.
- **Each handle is bound in policy to a specific tool, a specific argument field, and a destination.** Substitution happens only when all three match. A handle appearing in any other field or sent to any other destination is `HARD_BLOCK`. Without this binding, an injected agent can route a real secret to an attacker-chosen URL.
- Substitution happens immediately before bytes are written to the socket and the plaintext is zeroed afterwards.
- Canary tokens are planted in decoy `.env` paths. Any read or transmission of a canary triggers global lockdown and a ledger alert.

### Layer 8: Sandbox Runner (`internal/sandbox`)

**Objective:** OS-level containment of MCP server processes. This is the actual enforcement boundary.

Capability levels:

| Level | Meaning |
|---|---|
| L0 | No isolation |
| L1 | Filesystem confinement |
| L2 | L1 plus network denied |
| L3 | L2 plus syscall filtering |

Per-OS implementation, with honest limits:

- **Linux:** Landlock for filesystem (kernel 5.13+). Landlock network rules need kernel 6.7+; below that, deny sockets with a seccomp-bpf filter. Network namespaces need unprivileged user namespaces, which some distributions restrict by default (Ubuntu 24.04 does through AppArmor), so do not depend on them. Seccomp also blocks `ptrace`, `kexec_load`, and unauthorized socket creation.
- **macOS:** `sandbox-exec` with Seatbelt profiles. It is deprecated by Apple but functional, so it is **best-effort**, with a migration plan in section 12.
- **Windows:** AppContainer with a low-integrity token, plus a Job Object for process-tree limits.

Rules:

- Default is `network: deny` for every local MCP server.
- `sylenix-ctl doctor` reports the achievable level per server on the current machine.
- If the achievable level is below `sandbox.min_level`, the server **does not launch**. The only override is an explicit waiver recorded in the ledger as `UNSANDBOXED`.

### Layer 9: Evidence Ledger (`internal/ledger`)

**Objective:** a tamper-evident audit trail that supports security-safeguard and audit obligations under India's DPDP Act 2023 and SOC 2 Type II. It provides evidence. It does not by itself make anyone compliant, and any compliance claim needs review by counsel.

- Append-only WAL. Each record carries `prev_hash`, which forms a hash chain. Batches of records are periodically rolled into a Merkle tree, and the signed root is flushed to external immutable storage (S3 Object Lock, Azure immutable blobs, or an RFC 3161 timestamping authority).
- **Argument-derived values are never stored as plain hashes.** Low-entropy arguments (phone numbers, IDs) can be brute-forced from a bare SHA-256. The ledger stores `ActionRef = HMAC-SHA256(ledger_key, ActionHash)`, and the raw `ActionHash` stays in memory only. `ledger_key` is per-tenant and lives in the vault or TPM.
- Records contain no raw arguments, secrets, or PII; only keyed hashes and canonical schema paths.

```go
type LedgerRecord struct {
    SequenceNumber uint64    `json:"seq"`
    Timestamp      time.Time `json:"ts"`
    ActionRef      [32]byte  `json:"action_ref"`   // HMAC of ActionHash, not the hash itself
    ClientIdentity string    `json:"client_id"`
    EffectClass    string    `json:"effect"`
    Tainted        bool      `json:"tainted"`
    Confidential   bool      `json:"confidential"`
    Coverage       string    `json:"coverage"`     // full | partial
    SandboxLevel   string    `json:"sandbox"`      // L0..L3, or UNSANDBOXED
    Decision       string    `json:"decision"`     // ALLOWED, BLOCKED, HITL_APPROVED
    PrevRecordHash [32]byte  `json:"prev_hash"`
    KeyClass       string    `json:"key_class"`    // hardware | software
    Signature      []byte    `json:"sig"`
}
```

- Signing uses a Secure Enclave or TPM key where one exists. Where none exists (many VMs, some arm64 Linux hosts), fall back to a software key in the OS keychain and record `key_class: software`. Compliance mode can require `hardware` and refuse to start otherwise.
- The ledger append is asynchronous; the hot path only enqueues.

---

## 7. Canonical data models (`pkg/protocol`)

```go
package protocol

import (
    "encoding/json"
    "sync"
    "time"
)

// JSONRPCRequest is any incoming frame. Params are decoded by Method, because
// tools/list, initialize, and notifications do not share tools/call's shape.
type JSONRPCRequest struct {
    JSONRPC string          `json:"jsonrpc"`
    ID      json.RawMessage `json:"id,omitempty"` // absent for notifications; echoed back exactly
    Method  string          `json:"method"`
    Params  json.RawMessage `json:"params,omitempty"`
}

// ToolCallParams is the decoded Params for Method == "tools/call".
type ToolCallParams struct {
    Name      string                 `json:"name"`
    Arguments map[string]interface{} `json:"arguments"`
    Meta      map[string]interface{} `json:"_meta,omitempty"`
}

// Decision is ordered by strictness. Higher is stricter.
type Decision uint8

const (
    DecisionAllowFastPass Decision = iota
    DecisionAllowInspected
    DecisionRequireApproval
    DecisionHardBlock
)

// Tighten returns the stricter of the two decisions. It is the ONLY way advisor
// output may influence a decision. "No signal" from the advisor is
// DecisionAllowFastPass, which leaves the base decision unchanged.
func Tighten(base, advisory Decision) Decision {
    if advisory > base {
        return advisory
    }
    return base
}

// SessionContext tracks latches and grants. It must be safe for concurrent use.
type SessionContext struct {
    mu                     sync.RWMutex
    SessionID              string
    HostProfile            string // mediated_only | partial
    TaintLatched           bool
    ConfidentialityLatched bool
    TaintedOrigins         []string
    ActiveGrants           map[[32]byte]CapabilityGrant
    EscalationCount        int
    ReviewRequired         bool
    CreatedAt              time.Time
    LastActivityAt         time.Time
}

type EvaluationResult struct {
    Decision      Decision
    Reason        string
    RuleID        string
    ViolatedLayer int
    ActionHash    [32]byte // in-memory only; never serialized to the ledger
    PExploit      float32
    Timestamp     time.Time
}
```

---

## 8. Performance budgets

### 8.1 Targets

Targets are p95 on the reference hardware profiles (section 8.2).

```
Latency_total = T_parse + T_manifest + T_deterministic + T_policy + T_flow + T_advisor <= 40.0 ms
```

| Stage | Budget (p95) | Notes |
|---|---|---|
| JSON-RPC parse | 0.8 ms | allocation-minimal parsing (`buger/jsonparser`) |
| Manifest and schema validation | 0.5 ms | precomputed SHA-256 lookup |
| Deterministic checks (classifier + verifier) | 1.2 ms | path and AST invariants |
| Policy evaluation (Cedar) | 0.5 ms | compiled policy set |
| Flow controller (taint engine) | 1.5 ms | Aho-Corasick |
| Risk Advisor | 35.0 ms | ambiguous band only |
| **Total with advisor** | **39.5 ms** | **under the 40 ms ceiling** |
| **Total fast path (no advisor)** | **4.5 ms** | **most calls** |
| Ledger append | async | enqueue only on the hot path |

The 35 ms advisor budget is a target, not a promise. If the chosen model does not meet it on a reference profile, change the model or the profile. Do not relax the measurement.

### 8.2 Reference hardware

Define reference profiles in `test/benchmarks/REFERENCE_HARDWARE.md`: at minimum one Apple Silicon laptop, one x86_64 server with AVX2, and the weakest officially supported machine. Latency claims are valid only against these.

### 8.3 Build and packaging

- `sylenix-guard` and `sylenix-ctl` are static pure-Go binaries and can be cross-compiled.
- `advisor-worker` uses Cgo and ships with a matching ONNX Runtime shared library plus the model and its checksum. Build it natively per target in CI (a matrix job), not by cross-compiling from one machine.
- `sylenix-approve` is a small per-OS helper using native APIs, which keeps the main binary Cgo-free.
- "Self-contained" therefore means: one static main binary, plus an advisor bundle (worker, runtime library, model) that ships next to it.

---

## 9. Testing and verification

1. **Hermetic tests.** Unit tests under `internal/` use no external network. Use mock process pipes and virtual filesystems.
2. **Positive and negative fixtures** for every rule in `test/fixtures/`.
3. **Property tests.**
   - `Tighten(base, x) >= base` for all inputs.
   - Latches never clear within a session.
   - No code path other than `Tighten` consumes advisor output (enforced with a static check in `make lint`).
4. **Fuzzing** (`make fuzz`): JSON-RPC parser, path verifier, SQL verifier, sanitizer, canonical JSON.
5. **Security benchmarks** (`make test-security-ablation`, `make bench`): run InjecAgent and AgentDojo with layer-by-layer ablation. Report **all** of the following, never ASR alone:
   - Attack Success Rate (ASR) on state-mutating sinks. Target: 0.0% in the deterministic configuration.
   - Benign task completion rate (utility).
   - Utility under attack.
   - Approvals per session.
   - Added latency at p50, p95, p99.

   A configuration that blocks everything also scores 0.0% ASR, so ASR without utility is meaningless. CI fails when utility, utility-under-attack, or approvals-per-session regress past the limits in `test/benchmarks/thresholds.yaml`. Pin dataset versions. No public performance claim may be made unless `make bench` reproduces it.
6. **Process hygiene.** On SIGINT, SIGTERM, or panic, all descendant processes are killed via process-group signal (`syscall.Kill(-pgid, syscall.SIGKILL)`). Test this.

---

## 10. Errors and fail-closed behavior

Blocked actions return a valid JSON-RPC 2.0 error and must never crash the client.

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32000,
    "message": "Execution halted by Sylenix Guard",
    "data": {
      "rule": "RULE_TAINT_SINK_VIOLATION",
      "action_ref": "a8f3b204c..."
    }
  }
}
```

Error data goes to a channel the model can read, so keep it minimal. Return the rule ID and a reference only. Do not reveal policy contents, thresholds, allowlists, or detailed remediation text, which would give an attacker an oracle for probing the policy. Details go to the ledger and to `sylenix-ctl`.

| Code | Meaning |
|---|---|
| -32000 | Action blocked (policy or taint violation) |
| -32001 | Manifest mismatch (tool poisoning or rug-pull detected) |
| -32002 | Authorization denied (approval rejected, timed out, or no channel available) |
| -32003 | Sandbox violation (prohibited syscall or path boundary breach) |
| -32004 | Unclassified tool quarantined |
| -32005 | Sandbox capability below required level; server not launched |

---

## 11. Final instructions to autonomous agents

- Never bypass a layer. If a test fails, do not weaken the policy; fix the capability boundary.
- Never add external cloud dependencies to the core enforcement loop.
- Never route model output to a decision except through `Tighten()`.
- Keep the main binary pure Go and static. Isolate Cgo to `advisor-worker` and `sylenix-approve`.
- If you find a gap between what this document claims and what the code does, fix the document or the code in the same change. Do not leave them disagreeing.

---

## 12. Open decisions (do not implement guesses)

These are undecided. Ask before building them.

1. **Advisor model size**, ModernBERT-base versus large, pending latency measurements on the reference hardware.
2. **Remote approval relay** (`webauthn_remote`): transport, enrollment, and what the second device displays.
3. **macOS sandbox migration** away from `sandbox-exec`.
4. **Declassification ergonomics**: how admins define and audit `Trusted` origins without creating a standing hole.