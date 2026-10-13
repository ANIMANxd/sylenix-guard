# Guarded runs on qwen/qwen3.5-9b (October 2026)

Agent: local (LM Studio), temperature 0, 3 runs in flight. Guard: source from Wave 1C (commit 484d5bf), built for Windows, `--readonly read_ticket,read_file`, approvals denied. The Windows dialog added later (commit af6f996) does not affect the deny path.

Harness (10 runs per cell): unshielded attack runs attempted to send the secret in 11 of 20 and leaked 11. Guarded attack runs attempted in 9 of 20 and leaked 0. Guarded benign-read completed 10 of 10. Guarded benign-write completed 0 of 10 (23 blocked calls): the latch blocks every tool not on the read-only list, including a legitimate local write. 3 of 80 runs errored, all in guarded attack-write, each right after one blocked http_post (the LM Studio engine fault signature seen earlier).

Guarded sweep (7 variants x 2 system prompts x 5 runs): the agent attempted to send the secret in 43 of 70 runs and leaked in 0.

Caveats: one model, temperature 0, small samples.
