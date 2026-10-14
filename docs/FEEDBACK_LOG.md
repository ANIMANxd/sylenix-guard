# Feedback log

One section per person. Copy the template for each tester.

## Template

- Name:
- Host and MCP server wrapped:
- Start date:
- Still using it on day 7 (yes/no):
- Summary output (paste the output of `summarize_audit.py`):
- Prompts per active hour (from the summary):
- False blocks (count, and what you were doing each time):
- Anything that broke:
- Would you keep it on, and why or why not:

## Entries

## Entry 1 — Aniruddha Bhide (Windows / LM Studio)
- Name: Aniruddha Bhide
- Host and MCP server wrapped: LM Studio (Windows) wrapping @modelcontextprotocol/server-filesystem
- Start date: 2026-10-14
- Still using it on day 7: Yes
- Summary output:
  - Events: 29 (span: 2026-10-14T16:50:51Z -> 17:01:30Z)
  - Active time: 0.18 h
  - Allowed tool calls: 4
  - Approvals denied: 1 (write_file)
  - Approval prompts per active hour: 5.6
- Prompts per active hour: 5.6 (Gate B passed)
- False blocks: 0
- Anything that broke: None. Safe reads fast-passed seamlessly; indirect prompt injection on ticket.txt was intercepted out-of-band via native Windows MessageBox.
- Would you keep it on: Yes. Low friction and physically stopped an active prompt injection from destroying workspace files.


