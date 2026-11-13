# Security policy

## Reporting a bypass privately

Please do not open a public issue for a suspected security bypass.

Report it privately using one of these channels:

- Email **hello@sylenixlabs.com** with the subject line `Sylenix Guard security`.
- Use GitHub private vulnerability reporting on this repository:
  <https://github.com/ANIMANxd/sylenix-guard/security/advisories/new>

Please include:

- the affected commit or release, operating system, host and Guard flags;
- the smallest reproduction you can share (server, tool arguments and policy
  needed to trigger it);
- what you expected versus what happened, including the JSON-RPC error or audit
  event you saw;
- whether the issue is reproducible with default settings.

Do not send real secrets, credentials, private keys or third-party data. Redact
paths and values in logs; the audit log is designed to contain tool names,
argument key names, decisions and rule names, not argument values.

## What counts as a bypass

A bypass is a case where the Guard does not enforce the policy it documents.
Examples include:

- reaching a sink tool after taint without a grant, a covered scratch write or
  human approval;
- escaping `--allow-write-under` or a scoped grant through `..`, symlinks,
  junctions, Windows drive/UNC paths, case handling or argument
  misclassification;
- reaching a hard-blocked network, sensitive or protected persistence target
  through a grant, scratch rule, dialog decision or path alias;
- letting content from a server-to-client request or notification (sampling,
  elicitation, logging message or resource content) reach the model or user
  without latching taint;
- defeating pinning or quarantine by changing a tool definition without
  detection;
- making an unparseable, duplicate, batched, oversize or otherwise ambiguous
  frame pass through unblocked when it should fail closed;
- reading argument values from an audit log, or causing secrets/tokens/tool
  output to be written to the audit log or stderr;
- causing a fail-open crash, silent stream death or dialog failure that permits
  a call instead of denying it.

A model being persuaded by prompt injection is not by itself a Guard bypass.
The Guard contains actions on the MCP channel; it does not make a model
trustworthy, and it does not cover host built-in tools, attachments or pasted
text. See the limitations in `README.md` and `POC_SPIKE.md`.

## Red-team findings

We thank the red-team reviewers who reported the November 2026 findings. F1-F9
are fixed in **v0.1.2**:

| ID | Finding |
|---|---|
| F1 | Shared taint did not cover sibling server processes in one client session. |
| F2 | Read-class tools could read sensitive credential and config paths after taint. |
| F3 | `tools/call` key and name differentials could make the Guard check a different call than the server ran (F3a-F3e). |
| F4 | Padded arguments could hide the real target from the approval dialog. |
| F5 | Initialize instructions and server definition metadata did not latch taint. |
| F6 | A protected-target grant could cover more than the exact approved file. |
| F7 | Embedded resources, forged markers and additional invisible ranges bypassed result sanitisation (F7a-F7c). |
| F8 | Some read-class profile tools wrote files or used a database query path that was not read-only. |
| F9 | Profile matching truncated scoped package paths under `node_modules`. |

## Response expectations

We aim to acknowledge a private report within **3 working days**. After that we
will triage it, ask for any missing reproduction details, and tell you whether
we consider it a bypass, a documented limitation, or a non-security bug. We may
ask you to keep the report private until a fix or advisory is ready.

## Safe harbour

We will not pursue legal action or report you for good-faith security research
that stays within this safe harbour:

- you test only installs you own or have explicit permission to test;
- you do not access, modify, retain or disclose third-party data or systems;
- you do not use the finding to attack, extort or disrupt anyone;
- you give us a reasonable opportunity to fix the issue before public
  disclosure.

This is permission for good-faith research on your own installs only. It is not
authorization to test someone else's deployment, to run an attack against a
production system, or to break applicable law.
