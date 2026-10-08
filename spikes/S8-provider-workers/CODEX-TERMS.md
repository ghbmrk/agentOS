# S8-codex-terms: OpenAI terms on broker-held Codex tokens

**Status: in review (2026-10-08).** The source that would settle the question, OpenAI's Terms of Use, could not be read from this environment (see Sources). The recommendation below rests on CRED-5's own default (broker-held needs terms that *permit* it), not on a finding that OpenAI forbids it.

## Question
CRED-5 picks a custody mode per provider from its published terms. For Codex CLI signed in with a ChatGPT plan, do OpenAI's terms permit a broker process to hold and refresh the ChatGPT-managed tokens and inject them at egress (broker-held)? Or must the login stay in the Codex CLI's own process (worker-held)?

## Sources (all retrieved 2026-10-08)
| Source | Result |
|---|---|
| Terms of Use https://openai.com/policies/terms-of-use/ (and `/row-terms-of-use/`), Services Agreement `/policies/services-agreement/`, Usage policies `/policies/usage-policies/` | **Not read.** Egress is allowed now, but openai.com answers curl and WebFetch with a Cloudflare bot challenge (`403`, `cf-mitigated: challenge`). Getting past the challenge with a headless browser was refused by this session's permission classifier, and it was not attempted another way. |
| Codex auth docs https://developers.openai.com/codex/auth | **Not read.** `308` to `learn.chatgpt.com/docs/auth`, which the egress policy denies. |
| Help Center https://help.openai.com/en/articles/11369540-codex-in-chatgpt | **Not read.** Egress policy denies help.openai.com. |
| Codex repo, `main` branch, via raw.githubusercontent.com: `docs/authentication.md`, `README.md`, `codex-rs/login/src/auth/manager.rs` | Read (curl). |
| Sign in with ChatGPT (SIWC) docs https://developers.openai.com/siwc/token-sharing-open-source and `/sign-in` | Read (curl; quotes checked against the HTML text). |

## Findings
**What the text says (verbatim):**
1. `docs/authentication.md` (the whole file): "For information about Codex CLI authentication, see [this documentation](https://developers.openai.com/codex/auth)." The repo itself carries no auth or terms text.
2. `README.md`: "Run `codex` and select **Sign in with ChatGPT**. We recommend signing into your ChatGPT account to use Codex as part of your Plus, Pro, Business, Edu, or Enterprise plan."
3. `manager.rs`: `const REFRESH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";` and `pub const REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR: &str = "CODEX_REFRESH_TOKEN_URL_OVERRIDE";`. Also the error string "Your access token could not be refreshed because your refresh token was already used. Please log out and sign in again."
4. `manager.rs` also has a mode for tokens supplied from outside: "/// Pluggable auth provider used by `AuthManager` for externally managed auth flows.", "/// Externally managed ChatGPT tokens are normalized to [`AuthMode::Chatgpt`].", "externally provided auth is never loaded from auth storage" (`AuthMode::ChatgptAuthTokens`).
5. SIWC: "ChatGPT plan usage is an optional capability within Sign in with ChatGPT. In addition to identity scopes, your open-source app can request permission to use the user's ChatGPT plan for eligible Responses API requests. This does not grant access to their ChatGPT conversations or other account context. These docs explain ChatGPT plan usage for open-source and locally hosted apps. If you're interested in offering it in a paid or remotely hosted app, complete the interest form." Also on that page: "each issued client_id is bound to the authenticated user and the workspace selected during registration". On `/sign-in`: "Check the token response's granted scopes for chatgpt.tokens.use.direct before proceeding to inference."; "A valid ID token alone does not authorize ChatGPT plan usage."

**Inference (not in the text):**
- No source that was read either permits or forbids a broker holding the Codex CLI's own ChatGPT tokens. The ToU clauses that would decide it (account sharing, automated access, circumvention) went unread.
- OpenAI does document a way for software other than Codex to spend a user's plan: SIWC plan usage, with the app's own client ID and an inference-only scope (`chatgpt.tokens.use.direct`). It covers open-source and locally hosted apps; paid or remotely hosted apps go through an interest form. A broker that reuses the Codex CLI's client ID and tokens is outside that path. An AgentOS box is closer to "locally hosted" than "remotely hosted", but that is our reading, not OpenAI's.
- Refresh tokens are single-use (finding 3). The broker-held design in RESULT.md §2 already makes the broker the only refresher, through placeholder swap. A refresh that bypasses the broker would sign the owner out instead of leaking anything. The refresh endpoint can be overridden, which would make the swap simpler than terminating TLS for `auth.openai.com`.
- `ChatgptAuthTokens` (finding 4) suggests OpenAI expects some host processes to give Codex its tokens. Its intended users and terms are not documented in what was read.
- Worker-held custody also runs into CRED-5 W3. A Codex ChatGPT login is a full account login: RESULT.md §2 saw it call `wham/accounts/check`, `wham/settings/user`, plugin and MCP endpoints. It is not inference-scoped. The only inference-scoped plan token found (SIWC's `chatgpt.tokens.use.direct`) is issued to a registered app, not to the Codex CLI.

## Recommendation for CRED-5
**Recommendation, not a decision.** Record Codex as having **no qualified plan custody mode yet**:
- **Broker-held:** not qualified. CRED-5 allows it "only where the provider's terms permit a proxy to hold the login", and no permission was found. Silence is not permission.
- **Worker-held:** not qualified either, because W3 (inference-only scope) fails for a full ChatGPT login.
- **Interim route:** Codex runs with an OpenAI API key, broker-held as for any adapter, injected into declared inference endpoints only (ADP-10; CRED-1 unchanged). Plan use for Codex waits on the questions below. Claude stays worker-held per RESULT.md §2.

If Mark reads the ToU and it is silent on proxies too, the two choices are: (a) treat silence plus SIWC's "locally hosted" carve-out as enough for broker-held, which accepts some terms risk; or (b) ask OpenAI. The SIWC interest form or support are the only channels found.

## Open questions for Mark
1. Can you read https://openai.com/policies/terms-of-use/ in a browser (the challenge blocks agents) and paste the account-sharing, automated-access and circumvention clauses into #318? Or allow `learn.chatgpt.com` and `help.openai.com` in the environment, since the Codex auth page and Help Center now live there.
2. If the ToU is silent: broker-held on the "locally hosted" reading (a), or no Codex plan route until OpenAI confirms (b)?
3. Should W3 allow an exception for a provider with no inference-scoped CLI login, or does Codex plan use simply wait?
4. Is SIWC plan usage (AgentOS as a registered open-source, locally hosted app) worth a separate BOARD row? It does not fit CAP-11/CRED-5 today, which require the provider's official CLI.
