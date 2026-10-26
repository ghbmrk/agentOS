# TN-account-plan: setup's account plan from DKIM-authenticated mail metadata

Board row: issue #3189 (SPEC §12.1 step 7; CLK-9, CLK-10, CLK-14, ONB-3, DEV-8, PLN-3, PLN-7; serves A22). Tier A. Release. Three slices, each one session and one PR: **(a)** the plan builder and the known-services table, **(b)** the page, **(c)** the graph hand-off. Slice (c) starts only after #2857 (TN-graph) merges. #2860 (TN-mailreset) needs this row.

## Problem

Setup's step 7 offers one screen of the owner's frequently used accounts: payments first, then the optional mailbox, then the accounts the owner's mail shows they use. The kernel prepares it deterministically, with no planner, from sender and header metadata only. Nothing on main does this yet. The Gmail API mailbox (#2851) and its OAuth sign-in (#2852) are merged, so the box can already hold a `gmail.metadata` grant (the `watch` use in `broker/clerk/inbox/gmailauth.go`). It does not have a table of known services, a sender-authentication rule that works on metadata alone, a plan, a screen, or a hand-off to the owner's graph.

## Design

**Where it runs.** On this codebase, "kernel-only" means the keeper domain (D-154, D-157): the kernel and the clerks. The mail clerk process holds the grant (CLK-1). It reads the metadata, authenticates each sender and builds the plan. Only plan items cross its socket: table IDs, fixed wording and a source tag. No mail text, address, subject or count crosses. Planners never see the plan or its inputs. The plan builder is a new package, `broker/clerk/accounts`. It is pure: it does no I/O and imports only the standard library. It sits outside `tools/trusted_core.txt`'s roots and is not linked by them, so the trusted core's lines do not grow. If `python3 tools/trusted_base.py` shows the core growing, the builder stops and asks for a D-159 row before going on.

**Sender authentication under `gmail.metadata` (a decision this brief makes; reviewers check it).** `gmail.metadata` returns header fields but no body. Without the body, the box cannot verify a DKIM signature's body hash itself, and asking for `gmail.readonly` to get the body would break CLK-9, which requires the narrowest grant. So "DKIM-authenticated" here means the mailbox provider's own verdict, read the way `dmarcPass` in `broker/clerk/inbox/alert.go` already reads DMARC:
- Only the **topmost** `Authentication-Results` field counts, and only if its authserv-id equals the mailbox declaration's `AuthServ` (`mx.google.com` for Gmail). If `AuthServ` is empty, nothing matches (fail closed).
- A sender is authenticated for domain *d* when that field carries a `dkim=pass` result whose `header.d` is *d*. Without `header.d`, *d* is the domain of `header.i`. The From domain must also be *d* or a subdomain of *d*.
- Parse with the inbox's existing `parseAuthResults`. A `dkim=pass` that sits inside a comment or a quoted string is not a result. #2681 item 5 and `broker/mail/organize_test.go`'s cases show the attack shapes to copy into tests.
- Over IMAP (the *Full power* fallback, DEP-3) the same rule reads the same field from the headers. This slice does not add DNS-backed DKIM verification.

**What is read.** One declared list call covers all mail except spam and trash, newest first, with no `q` parameter. Gmail refuses `q` under the metadata scope; if the fake's contract case shows otherwise, record that in ASSUMPTIONS.md. The list stops after `PlanMails = 1000` mails. Each listed mail gets one metadata get with `metadataHeaders=From&metadataHeaders=Authentication-Results`. Both calls are new entries in `GmailCalls` and do not change the existing calls. The reader returns only the set of authenticated domains. Display names, local parts, subjects and dates are dropped in the clerk. A page cap like `gPagesMax` bounds the listing. A mail that disappears between list and get is skipped. A refused refresh is reported as grant death (A22 Gmail clause): there is no plan and the reason is typed, never a partial plan.

**Known-services table (CLK-14), owned by this row; #2860 extends it.** The table ships as data, `broker/clerk/accounts/known.json` (`go:embed`), and never as Go branches per provider, so no provider name enters trusted-base code. Fields (all fixed wording comes from the table):
- `id` (stable), `name` (the wording shown), `kind` (`money`, `identity`, `mail`, `utility`, `shopping`, `travel`, `other`), `group` (`payment`, `mailbox` or `account`).
- `domains`: the sender domains that authenticate it. A domain matches exactly or as a parent of the authenticated domain.
- `signin`: the https hosts its sign-in may go to (see Endpoints below).
- `narrower`: true when the provider offers a credential narrower than the owner's (CLK-9).
- `route`: `oauth`, `imap`, `password` or `none`.
- `at_home`: a password-only site or device pairing.
- `ongoing`: its data feeds proactive notices.
- `implied_by`: device kinds that imply it, such as `ev-charger` or `thermostat` implying "Electric utility".

Decoding uses `DisallowUnknownFields`, so #2860 adds its fields (recovery paths, second-factor recovery, failure domains, cut-off and alerts pages, lock or locate power, who pays, compellers, one-sided-change record) on purpose, in the struct and in the validator. Validation at load:
- ids are unique;
- domains are lower-case A-label hostnames and no domain sits in two entries;
- signin hosts are hostnames with no scheme, path or port;
- an entry with `route: imap` has `narrower: false`;
- the payment-card, wallet and mailbox entries exist.

The seed is small: the payment card, a payment wallet, the CLK-8 mailbox, Gmail, one utility implied by devices, and the services the fakes model. More services are later data-only PRs.

**The plan.** `accounts.Build(table, domains, devices)` returns ordered `Item`s: `{ID, Name, Kind, Group, Source (mail|device|always), Preselected, Label, Advice}`.
- **Order:** the payment card (KEY-2), then the wallet (CH-10), then the optional mailbox (CLK-8), then accounts in table order. This is deterministic and repeatable.
- **Preselection:** the card counts as preselected. Other items are preselected only when `at_home` or `ongoing` is set. The mailbox is not preselected.
- **Label:** *Narrower than you, watched* when `narrower` is set and `route` is not `imap`; otherwise *Full power, same as yours* (an IMAP account is always *Full power*, A22). An item with a narrower route carries CLK-9's fixed advice to connect it.
- **Device-implied items:** device kinds come from the ONB-3 plan step. That step is not on main, so slice (b) passes an empty list until it is. An unknown kind implies nothing. An item found in mail and implied by a device appears once, tagged `mail`.
- **Fixed wording only (DEV-8):** every string in an `Item` comes from the table or a package constant.

**Endpoints.** `Entry.SignInAllowed(u *url.URL)` is true only for https and a host in the entry's `signin`. Slice (b) refuses any Set up link that fails it, before showing the link.

**Unconnected accounts for guests (PLN-7, PLN-3).** `accounts.Unconnected(plan, connected)` returns `Listing{Service, Kind}` only, the wording "exists, not connected", and nothing else: no credential, key, domain or count. Serving it through guests' `resources` needs a `resources` server that main does not have. Slice (a)'s PR files that as a `work-item` issue labelled `class:release`. The issue cites PLN-3: the list is private content, sent only to callers allowed private content.

**The page (slice b, integration owner).** One screen on the box's Wi-Fi page, built like the device plan, shown after step 6 and the ONB-3 plan step:
- New op `localapi.OpAccountPlan`, through localsrv, `accountsock.Gmail.Plan` and the mail host's `account.plan` op in `broker/clerk/run`, which runs the reader and `Build`. The clerk keeps the plan in memory for its own lifetime and rebuilds it after a restart. Nothing is persisted.
- Each item shows **Set up** and **Later**, its label and its advice. Set up on an item whose route the box has (today Gmail's `oauth`, reusing `Begin`/`Finish`) runs that sign-in, checked against `SignInAllowed`.
- Where no route is built yet, Set up records the choice and the item shows the fixed line "Listed: I'll ask to connect it when a task first needs it." No step that cannot work is named (UX recurring kind).
- Later leaves the item unconnected, and it then appears in `Unconnected`.
- The card, wallet and mailbox items link to their own pages where those exist on main, and otherwise follow the same rule.
- Slice (b) touches `localapi`, `localsrv` and `localui`, which the open PRs #3172 and #3173 also touch, so it starts only after both merge or close (D-111). If it needs `cmd/agentosd` wiring beyond `pageAccounts`, it joins the serial agentosd chain.

**Graph hand-off (slice c, after #2857).** Each plan item becomes an account node, and its provider a provider node, in #2857's node types. Each fact carries its source (CLK-10): `declaration` for table facts, and `observation` for "found in the owner's mail", the clerk's own observation. A device-implied item also gets an edge to its device node. Unanswered table fields stay absent, not false, so the scoreboard counts them as unverified. Slice (c) reads #2857's merged API and writes its adapter in `broker/clerk/accounts`. It never edits `broker/owner/graph`. If #2857's types cannot carry a source per fact, that is a question on #2857, not a local type.

### Lifecycle (one owner: slice b)

| Stage | Outcome |
|---|---|
| First setup, step 7, Gmail signed in under `watch` | Plan built once in the mail clerk; screen shows it; Later items listed as unconnected |
| Page reopened | Same plan from the clerk's memory, same order |
| Mail clerk restarted | Plan rebuilt from the mailbox; same result for the same mail |
| Grant refused at refresh | No plan; typed grant-death reason; the screen says the sign-in ended, with the reconnect step that exists |
| Mailbox over IMAP | Same rule; the mailbox shows *Full power* |
| No mailbox signed in | Only the payment card, wallet, mailbox and device-implied items |

## Requirements (local IDs; SPEC §12.1 step 7, CLK-9, CLK-10, CLK-14, DEV-8, PLN-3, PLN-7)

Slice (a):
- **TN-account-plan-1.** A sender counts as authenticated for *d* only by a `dkim=pass` for *d* in the topmost `Authentication-Results` written by the declaration's authserv-id, with the From domain under *d*. A lower field, another authserv-id, an empty `AuthServ`, a pass in a comment or quote, a `dkim=fail`, or a From outside *d* counts for nothing.
- **TN-account-plan-2.** The Gmail reader uses only the two new declared metadata calls (no `q`, no `format=full` or `raw`), stops at `PlanMails` and the page cap, skips a mail that has gone, and returns only domains. A refused refresh yields grant death and no plan.
- **TN-account-plan-3.** The table loads from the embedded JSON with unknown fields refused and every validation rule above enforced. Trusted-base code has no provider name outside the table and test fakes.
- **TN-account-plan-4.** `Build` orders payment card, wallet, mailbox, then table order; preselects only the card and `at_home` or `ongoing` items; labels by `narrower` and `route`, so IMAP is always *Full power*; adds device-implied items once. It is deterministic.
- **TN-account-plan-5.** No string in a plan carries bytes from mail. `Unconnected` carries only service name, kind and the fixed wording. `SignInAllowed` refuses non-https and undeclared hosts.

Slice (b):
- **TN-account-plan-6.** The mail clerk serves `account.plan`, and only plan items cross its socket. The page shows one screen with Set up and Later per item, label and advice. Set up runs only a declared, allowed sign-in, and otherwise shows the fixed listed line. The lifecycle table holds end to end on the fakes.

Slice (c):
- **TN-account-plan-7.** Every plan item reaches #2857's graph as account and provider nodes with a source on each fact: `declaration` for table facts, `observation` for found-in-mail. #2857's engine counts the item's unanswered fields as unverified.

## Acceptance tests

**Acceptance tests:**
- TN-account-plan-1 `broker/clerk/inbox::TestPlanSenderNeedsTopmostProviderDKIMPass`, a table test. It catches: a sender-added `Authentication-Results` below or above with another authserv-id; an empty `AuthServ` failing open; a pass hidden in a comment or quoted value; a From domain outside `header.d`; `header.i` used only without `header.d`.
- TN-account-plan-2 `broker/clerk/inbox::TestPlanReaderReadsOnlyDeclaredMetadata` (the fake logs every request, so it catches a `q`, a full or raw get, or reading past `PlanMails`); `TestPlanReaderSkipsAMailGoneBetweenListAndGet`; `TestPlanReaderReportsGrantDeath` (catches a partial plan on a refused refresh); `TestPlanReaderReturnsOnlyDomains` (a canary display name and subject never reach the result).
- TN-account-plan-3 `broker/clerk/accounts::TestKnownTableLoadsAndValidates` (catches a shipped table that breaks a rule); `TestKnownTableRefusesUnknownFieldsAndEachBrokenRule` (one bad table per rule: a duplicate id, a shared domain, an upper-case domain, a signin host with a scheme or port, IMAP marked narrower, a missing card, wallet or mailbox).
- TN-account-plan-4 `broker/clerk/accounts::TestBuildOrderPreselectAndLabels` (catches the mailbox preselected, an IMAP entry labelled *Narrower* (the A22 fence), and order depending on input order); `TestBuildDeviceImpliedOnce`.
- TN-account-plan-5 `broker/clerk/accounts::TestPlanCarriesNoMailBytes` (a canary in every input domain's surrounding mail fields is absent from every `Item` string); `TestUnconnectedCarriesOnlyNameAndKind` (reflection: exactly the two fields, so a later field added to `Listing` fails); `TestSignInAllowedRefusesUndeclaredHosts`.
- TN-account-plan-6 `broker/clerk/run::TestAccountPlanOpSendsOnlyItems`; `broker/localui::TestAccountPlanScreenSetUpAndLater`; `broker/localui::TestAccountPlanSetUpRefusesUndeclaredLink`; `broker/localsrv::TestAccountPlanLifecycle` (one case per lifecycle row).
- TN-account-plan-7 `broker/clerk/accounts::TestGraphHandOffSources`; `TestGraphHandOffUnansweredIsUnverified` (against #2857's engine on a fixture household).
- Each slice's PR names one mutant per defence and shows it fails a listed test (potency recurring kind): drop the topmost-only check, drop the authserv-id check, accept `header.i` alongside a mismatched `header.d`, preselect the mailbox, or label IMAP narrower.

## Scope

**Slice (a):**
- `broker/clerk/accounts/` (new): `accounts.go`, `known.json`, `accounts_test.go`, `testdata/`, `ASSUMPTIONS.md`.
- `broker/clerk/inbox/`: `plansenders.go` (new) and `plansenders_test.go` (new); `gmail.go` (the two new calls in `GmailCalls`); `gmailtest/gmailtest.go` (metadata answers with several `metadataHeaders`, and the request log); `ASSUMPTIONS.md` (TN-account-plan rows).
- This brief.

**Slice (b):**
- `broker/localapi/localapi.go` (and `localapi_test.go`).
- `broker/localsrv/`: `accounts.go`, `accounts_test.go`, `accountsock/accountsock.go`, `accountsock/accountsock_test.go`, `ASSUMPTIONS.md`.
- `broker/clerk/run/`: `gmailsignin.go` or a new `accountplan.go`, plus its test, and `ASSUMPTIONS.md`.
- `broker/localui/`: a new `accountplan.go` and `accountplan_test.go`, `pages.go`, `accounts.go`, `ASSUMPTIONS.md`.
- `cmd/agentosd` only if the existing `pageAccounts` wiring cannot carry the op, and then serially.

**Slice (c):**
- `broker/clerk/accounts/graph.go` and `graph_test.go`.
- `broker/clerk/accounts/ASSUMPTIONS.md`.

**Guard files:**
- `tools/risk_tier.py`: none. `broker/clerk/...` is already tier A.
- `tools/g1_scope_g2.txt`: none. `allow broker/clerk/` covers it.
- `broker/daemon/arc2_test.go`: none for (a). (b) and (c) add only the import rules their wiring forces.
- `tools/trusted_base_parsers.txt`: one line, `inert github.com/ghbmrk/agentos/broker/clerk/accounts -- decodes only its own embedded table`, if `trusted_base.py` asks for it.
- `broker/clerk/imports_test.go`: unchanged. `accounts` imports neither `inbox` nor a mail parser, and the check path does not import `accounts`.

**Out of scope:**
- Serving `Unconnected` through guests' `resources` (follow-up issue, filed by (a)).
- The ONB-3 device plan step itself.
- Connecting services that have no route on main.
- The table fields #2860 owns.
- Anything under `broker/owner/graph` (#2857 is building there).

## Dependencies and usage

Needs: #2851 and #2852 (merged). (b) also needs #3172 and #3173 merged or closed (D-111, for `localapi`, `localsrv` and `localui`). (c) needs #2857 merged. Estimates (checkpoints, not ceilings): (a) about 110k, (b) about 130k, (c) about 60k tokens.
