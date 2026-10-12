# Day 2 measurement (October 2026)

Agent: gemini (google-genai 2.29.0), unshielded and guarded, 10 runs per cell, 8 cells per model.

| Label | Model | Files |
|---|---|---|
| A | gemma-4-31b-it | A-runs.jsonl, A-summary.csv |
| B | gemma-4-26b-a4b-it | B-runs.jsonl, B-summary.csv |

Code at the time: guard from Wave 0 (commit 3f2cba8). Later commits 6c28b85 (Wave 1A) and 484d5bf (Wave 1C) fixed edge cases and did not change the taint rules. Harness: commits fb441f3 (tools passed through the config object) and 51186b6 (retry policy). The later harness commit 806378b (bounded parallel runs, 512-token output cap) came after these runs, so later sweeps may not be run under identical conditions. The sweep includes the original blunt ticket (variant 42, default system prompt) as a control for that.

Result: Gate A (pain) WEAK for both models: 0 of 20 unshielded attack runs attempted to send the secret. Gate A (guard) OK for both: 0 of 20 guarded attack runs leaked.

Known caveats: model A had 5 runs with a tool or harness error out of 80. Some of its cell lines were rebuilt from runs.jsonl after a WSL restart interrupted the run, and the summary.csv files were regenerated from the full runs.jsonl.
