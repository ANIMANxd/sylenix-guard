# Sylenix Teams: minimal policy service and audit collector

`teams/` is the paid-tier policy service and audit collector. It is a separate
Go package and binary (`bin/sylenix-teams`). The Guard binary gains optional team
and audit flags; without them its behaviour is unchanged.

## Signed policy format

The service uses the repository's existing signed-policy format:

- `policy.yaml` is the versioned policy file already understood by Guard.
- `policy.yaml.sig` is a raw 64-byte Ed25519 signature over the exact bytes of
  `policy.yaml`.

Over HTTP the two files travel in one JSON envelope:

```json
{"policy":"<base64>","signature":"<base64>"}
```

The service verifies the signature before storing a published policy and again
before serving it. Guard verifies the signature before parsing the policy and
before using a cached copy. The service does not parse or validate the YAML; a
signed but malformed policy is rejected by every Guard, which keeps its last
good policy.

## Serve

```bash
sylenix-teams serve \
  --listen 127.0.0.1:8443 \
  --tls-cert /etc/sylenix/tls.crt \
  --tls-key /etc/sylenix/tls.key \
  --tokens /etc/sylenix/team-tokens \
  --pubkey /etc/sylenix/team.pub \
  --data-dir /var/lib/sylenix/policies
```

The server refuses to start without a TLS certificate and key. It exposes the
policy endpoint and the audit collector:

- `GET /v1/policy` returns the signed policy for the team identified by the
  bearer token.
- `PUT /v1/policy` publishes a signed replacement for that team.
- `POST /v1/events` accepts a batch of sanitized audit events.
- `GET /v1/events` exports those events as JSON.
- `GET /v1/events/syslog` exports them as RFC 5424 lines.

There is no plaintext HTTP mode.

### Tokens

Tokens are high-entropy bearer secrets. Only their SHA-256 hashes are stored:

```bash
# Read the token from stdin so it does not appear in shell history or argv.
printf '%s' "$TEAM_TOKEN" | sylenix-teams token hash --team acme
# acme:9d5f...64-hex-characters
```

```text
# /etc/sylenix/team-tokens
acme:9d5f...
beta:41c0...
```

Blank lines and `#` comments are allowed. Duplicate teams, plaintext tokens and
malformed hashes are rejected. Token comparison is constant-time.

The same per-team token authorizes policy `GET`/`PUT` and event
`POST`/`GET`/syslog export. Treat it as an admin credential: do not put it on a
machine where a developer can read it. Separate pull-only, publish-only and
audit-read tokens are not implemented yet.

## Publish

```bash
sylenix-guard policy sign --policy policy.yaml --key /secure/team.key
sylenix-teams publish \
  --url https://policy.example.com/v1/policy \
  --policy policy.yaml \
  --token-file /secure/team.token \
  --ca /etc/sylenix/internal-ca.pem \
  --pubkey /etc/sylenix/team.pub
```

`publish` uses HTTPS only, refuses redirects, verifies the local signature when
`--pubkey` is supplied, and never prints the token. The server returns `400` for
a bad envelope or signature and `401` for a missing or wrong token.

## Audit event collector

The same service hosts the team audit collector:

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/events` | `POST` | Accept a JSON array of sanitized events from a Guard. |
| `/v1/events` | `GET` | Export the caller team's events as a JSON array. |
| `/v1/events/syslog` | `GET` | Export the caller team's events as RFC 5424 lines for a SIEM. |

All three require the same per-team bearer token as the policy endpoint. Events
are stored in `events-<team>.jsonl` under `--data-dir`, mode `0600`, append-only.
The collector rejects unknown fields, so a batch carrying arguments or content
is refused rather than stored.

The only fields are:

```json
{
  "timestamp": "2026-11-10T12:00:00Z",
  "developer_id": "dev-01",
  "server": "demo",
  "tool": "write_file",
  "decision": "block",
  "reason_code": "TAINT_SINK",
  "taint_state": "tainted"
}
```

`decision` is one of `allow`, `block`, `deny`, `taint`, `clear_taint` or `info`.
`taint_state` is `clean` or `tainted`. Argument values, content, URLs, notes and
tool output are never part of this schema.

### Guard shipping

```bash
sylenix-guard \
  --name filesystem \
  --state-dir ~/.sylenix-poc \
  --audit-url https://policy.example.com/v1/events \
  --audit-token-file /etc/sylenix/guard.token \
  --audit-ca /etc/sylenix/internal-ca.pem \
  --audit-id dev-01 \
  --audit-interval 5s \
  --audit-batch 50 \
  -- npx -y @modelcontextprotocol/server-filesystem ~/work
```

| Flag | Meaning |
|---|---|
| `--audit-url URL` | HTTPS collector endpoint. Required to enable shipping. |
| `--audit-token-file PATH` | Collector token file. Falls back to `--team-token-file`, then `SYLENIX_TEAM_TOKEN`. |
| `--audit-ca PATH` | Optional extra CA bundle. Falls back to `--team-ca`. |
| `--audit-id ID` | Machine/developer ID attached to each event. Defaults to `user@host`. |
| `--audit-interval DURATION` | Maximum time between batches. Default `5s`. |
| `--audit-batch N` | Events per batch. Default `50`. |

Every event is appended to `<state-dir>/audit-outbox-<name>.jsonl` before it is
sent. The sender batches, retries with exponential backoff (1 second up to 1
minute), and drains the outbox after a restart. A collector outage therefore
loses no buffered events and never blocks the proxy decision path. Delivery is
at-least-once: a crash after the collector accepts a batch but before the local
outbox is truncated can resend it.

Syslog export uses `local0.info` (`PRI 134`) for normal events and
`local0.warning` (`PRI 132`) for blocks/denials, with the event fields in a
`sylenix@32473` structured-data element.

## Guard flags

```bash
sylenix-guard \
  --name filesystem \
  --state-dir ~/.sylenix-poc \
  --team-url https://policy.example.com/v1/policy \
  --team-token-file /etc/sylenix/guard.token \
  --team-pubkey /etc/sylenix/team.pub \
  --team-ca /etc/sylenix/internal-ca.pem \
  --team-interval 15m \
  --policy ./local-tightening.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem ~/work
```

| Flag | Meaning |
|---|---|
| `--team-url URL` | HTTPS policy endpoint. Plain HTTP is refused. |
| `--team-token-file PATH` | File containing the team bearer token. `SYLENIX_TEAM_TOKEN` is used when the flag is omitted. |
| `--team-pubkey PATH` | Team Ed25519 public key. Required with `--team-url`. |
| `--team-ca PATH` | Optional extra CA bundle for the policy service. |
| `--team-interval DURATION` | Pull interval. Default `15m`. Positive durations are accepted for tests and controlled deployments. |

`--team-url` requires an absolute `https://` URL with no userinfo, query or
fragment. Redirects are not followed.

## Pull, cache, and fail closed

- Guard pulls once before loading a policy, then every interval.
- A fetched policy must have a valid team signature, parse as policy version 1,
  and contain the `--name` entry when required.
- The last good policy and signature are cached as
  `<state-dir>/team-policy-<name>.yaml` and `.sig`.
- If the service is unreachable at startup, Guard uses the cached pair only
  after re-verifying its signature. A missing, tampered or wrong-key cache is a
  startup failure (exit 2); it never falls back to built-in defaults.
- A rejected refresh keeps the last good in-memory policy and records
  `team_policy_rejected`. It does not replace the cache.
- A valid change is swapped into an immutable in-memory snapshot. Tool calls
  already being evaluated finish against the old snapshot; later calls see the
  new one.

Audit events contain the tool name, decision, reason and policy version only:
`team_policy_loaded`, `team_policy_reloaded`, `team_policy_rejected`,
`team_policy_cache_error`, `team_policy_unavailable` and
`team_policy_loosen_ignored`. Tokens, policy bodies and tool argument values are
never written to the audit log.

## Local policy can only tighten

With `--team-url`, the local policy file (`--policy` or
`<state-dir>/policy.yaml`) is an overlay on the team policy. The following local
changes are accepted:

- Tool class equal to or stricter than the team class (`read` -> `write` /
  `egress` / `exec`; `write` or `egress` -> `exec`).
- `trust: false` where the team trusts a tool.
- `approval: deny` where the team uses `dialog`.
- `spotlight: true` where the team disables it.
- Additional `sensitive_paths` and `egress.deny_hosts`.
- A subset of the team's `egress.allow_hosts`, `allow_paths`, scratch roots and
  allowlist entries.
- More `path_keys` for a tool.

Anything that would loosen the team policy is ignored and recorded in
`team_policy_loosen_ignored`; it is not a startup error. Local-only tool entries
must be `class: exec`, because the unknown-tool default is already `exec`.

The same rule applies to local flags: `--readonly`, `--trust`,
`--approve dialog`, `--no-spotlight`, `--allow-write-under` and `--grant` are
applied only where they narrow the team policy. `--grant` seeds are dropped in
team mode.

## Limits

- The service stores one policy per team and one team signing key. Key rotation,
  revocation, multi-key trusts and per-team signing keys are not implemented.
- There is no rollback protection: an older signed policy can be replayed. The
  same limitation applies to the local signed-policy path.
- A token grants both pull and publish. Keep it off developer machines or add a
  separate pull-only role before relying on that boundary.
- TLS certificate issuance and renewal are the operator's responsibility. The
  Guard uses system roots plus an optional `--team-ca`.
- The service does not parse policy YAML. A signed but invalid policy is rejected
  by Guards and does not replace their last good policy.
- Local policy files are read once at startup, like the existing local policy.
  Editing the overlay does not hot-reload it; the next process start does.
- Policy pulls and audit delivery are HTTP polling. There is no push channel,
  long-poll, websocket or syslog TCP forwarder; SIEMs pull the syslog export.
- Audit delivery is at-least-once and the local outbox has no size cap. Keep an
  eye on the outbox on a long offline Guard; a full disk is a local availability
  failure, not a policy bypass.
- Collector event storage is append-only with no rotation or pagination. Archive
  or truncate `events-<team>.jsonl` according to your retention policy.
- `sylenix-guard install` and `doctor` know about the existing policy/signing
  flags, not the team or audit flags. Add those flags to a wrapper manually, or
  extend install in a later change.
