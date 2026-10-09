# Mark queue

Questions and actions only Mark can take, one line each, answerable in one word, with a recommendation (OPERATING §5). Mark answers the queue in one sitting; an answered question moves to DECISIONS.md and its line is removed. Actions stay until done.

## Questions

| # | Question | Recommendation | Source |
|---|---|---|---|
| Q1 | Adopt the CLAUDE.md lines for D-085 (release test, `recheck`, tooling and depth rule, idle limit, Mark queue, daily ledger reading)? An agent may not edit CLAUDE.md without your approval; the text is in the CONV-1 PR description. | yes | CONV-1 |
| Q2 | Approve the batched L1 spec-diff for D-079 to D-083 when CONV-4 opens it, and freeze first-release scope after it (new release requirements need your explicit promotion)? | yes | CONV-4 |
| Q3 | Close the stale non-CODEX-1 PRs on CONV-3's list (branches kept)? | yes, once the list is posted | CONV-3 |
| Q4 | Choose the licence (D-041; OSS-12 needs it before first public release, with upstream OpenClaw notices kept)? | Apache-2.0 if OpenClaw's own licence allows it (not yet checked) | CONV-5 |

## Actions

| # | Action | Unblocks |
|---|---|---|
| A1 | Add a usage reading to LEDGER.md today, then daily (none since 2026-10-04) | pacing, CONV-0, PILOT-S judgement |
| A2 | Hardware for S1: three unmodified PCs and the USB4 SSD, plus hands | S1 (A1), HW-6 |
| A3 | Two USB LTE modems and a SIM for S2 | S2 (A1, A3) |
| A4 | Claude and ChatGPT plan logins for the S8 live run | S8-live (A3, CAP-11), CAP-7 |
| A5 | S5's live run is denied by the cloud environment's network policy: add the hosts S5 names under the environment's settings, Network access, Allowed domains (https://code.claude.com/docs/en/cloud-environments#network-access) | S5 (A5, A13) |
| A6 | One test mailbox at a free mail provider (name the provider; account creation may need your phone number) | ADP-13 live run |
| A7 | The N95 reference box (GEEKOM Air12 Lite) for floor measurements | HW-4, P2-4-hw, S3 N95 timings |
