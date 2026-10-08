# S8-codex-terms: OpenAI terms on broker-held Codex tokens

**Status: escalated, blocked on network policy (2026-10-08).** No finding on the terms is made here.

## Question
CRED-5 picks a custody mode per provider from its published terms. For Codex CLI signed in with a ChatGPT plan: do OpenAI's terms permit a broker process to hold and refresh the ChatGPT-managed tokens and inject them at egress (broker-held), or must the login stay in the Codex CLI's own process (worker-held)?

## What was tried (2026-10-08, from this cloud session)
| URL | Tool | Result |
|---|---|---|
| https://openai.com/policies/row-terms-of-use/ | curl, WebFetch | `CONNECT tunnel failed, response 403` / `EGRESS_BLOCKED` (openai.com) |
| https://openai.com/policies/terms-of-use/ | curl | `CONNECT tunnel failed, response 403` |
| https://developers.openai.com/codex/auth | curl, WebFetch | `CONNECT tunnel failed, response 403` / `EGRESS_BLOCKED` (developers.openai.com) |
| https://raw.githubusercontent.com/openai/codex/main/docs/authentication.md | WebFetch | Reachable; contains only a link to developers.openai.com/codex/auth, no terms text |

The primary sources (Terms of Use, Services Agreement, usage policies, Codex auth docs) all live on `openai.com` or `developers.openai.com`, which this environment's egress policy blocks. Search-engine summaries or third-party copies would not meet the brief's bar (quotes from primary sources with retrieval dates), and S8's RESULT.md already records the search-summary reading as **unverified**.

## Decision recommendation for CRED-5
None yet. Until the terms are read, Codex has no qualified custody mode; the existing interim reading in RESULT.md §2 (broker-held candidate, unverified) stands as unverified.

## Needs Mark
1. An environment whose network policy allows `openai.com` and `developers.openai.com` (custom allowlist or full access), then re-run this package from its BOARD row. Same blocker as S5's live run and S8-live, so one custom policy may serve all three.
2. Alternatively, Mark reads the pages and pastes them into the thread; the builder then quotes them with Mark's retrieval date.
