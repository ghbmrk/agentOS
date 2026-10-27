# TN-account-plan-guests: the guests' `resources` server, first with unconnected accounts

Board row: issue #3194 (SPEC §12.1 step 7; PLN-7 Resources, PLN-3, REV-5, DEV-8, CLK-1). Tier A. Release. One session, one PR. Filed by #3189 slice (a); its parent brief is `briefs/TN-account-plan.md` ("Unconnected accounts for guests").

## Problem

`accounts.Unconnected` (broker/clerk/accounts) and the mail clerk's account plan (`broker/clerk/run/accountplan.go`, served to agentosd as `accountsock.Gmail.Plan`) are on main. Nothing serves the list to guests: main has no `resources` server. So §12.1 step 7's "an account found but left unconnected is listed to guests through `resources`" never holds, and a guest cannot propose a combination that uses such an account, which is what triggers step 8's first-use connection.

PLN-7 gives `resources` more than accounts: per granted route and clerk its kind, qualified classes, acceptance, latency, pool headroom, cost and concurrency, and connected and unconnected devices (DEV-2, DEV-10). None of those has a data source this row can read without other rows (routes have no measured scores on main, and ONB-3's device plan step is not on main). This row builds the server and its first section, unconnected accounts. Other sections are later rows that add a field to the same answer.

## Design (decisions this brief makes; reviewers check them, and the open questions are on #3194)

**Where it runs: a guest-plane broker tool, not a kernel step.** A new package `broker/resources` implements `guest.Tools` (by method set; it does not import `guest`) for one tool named `resources`. agentosd adds it to `registeredTools` (`broker/cmd/agentosd/tools.go`), beside the question and worker tools. The guest plane already supplies the caller's identity from its socket, never from the request (`guest.Tools`). The listing gives no reach (PLN-7: the enforcer still blocks every unconnected device and no clerk exists for an unconnected account), so there is nothing for the kernel's key check to admit. Making it a kernel verb would add a verb, a clerk and key admission for a read of box metadata, and grow the trusted core. SPEC calls it "a `resources` read step". Whether that means a kernel-checked step is question 1 on #3194. Build the tool unless the answer says otherwise.

**Who may read it (PLN-3, REV-5): reading raises the caller to private.** The listing is private content. Every call first raises the calling machine's label to private (`vm.Manager.RaiseLabel(machine, vm.Private)`, the same way the question tools' `Reveal` does in `broker/cmd/agentosd/questions.go`), and only then reads the plan. If the raise fails, the answer is a fixed refusal and nothing is read. The raise happens before every answer, including an empty list or a refusal, since even "nothing found" is derived from the owner's mail. From then on the machine's model calls go only to routes allowed private data, because the guest plane's model forward reads the raised label (`modelroute.Forward`'s `Label: m.DataLabel` in `openGuestPlane`). That is PLN-7's eligibility rule. The tool's description says so in one line: reading it makes this session private. A guest that wants to stay public does not call it. Raising rather than refusing a public caller is question 2 on #3194.

**What it reads.** `resources.Config.Plan func(ctx) (localapi.AccountPlanned, error)` is agentosd's existing `accountsock.Gmail.Plan` on the mail clerk's owner socket, the same value `pageAccounts` builds. When no mail clerk is configured, `Plan` is nil and the accounts section is an empty list. The clerk builds the plan at most once per account change and serves it from memory (`accountPlan`). A guest's call can trigger the first build after a clerk restart. That build is the page's build: the same declared metadata calls and bounds, with no new mail read. A call has a 10-second deadline.

**What crosses to the guest (DEV-8, CLK-1).** For each plan item, in plan order, the server keeps an item only when all of these hold:
- its `Source` is `mail` or `device` (never `always`: the card, wallet and mailbox are offers, #3237, which also settles the #3197 item 4 pointer on #3194);
- it is not `Connected`;
- its `ID` is in the shipped table (`accounts.Known()`).

Each kept item becomes `{service, kind, status}`. `service` and `kind` are the **table's** `Name` and `Kind` for that ID, never the strings the clerk sent. `status` is `accounts.NotConnected`. The server builds `[]accounts.Item` from the answer and calls `accounts.Unconnected` for the filter, then replaces the wording from the table. So a compromised or confused mail clerk, which handles hostile mail, can at worst drop or reorder table entries. It can never put a byte of its own into a guest's context. More than `localapi.MaxPlanItems` items, or a typed `Reason`, gives the fixed refusal "unconnected accounts are unavailable now". There is no partial list. The answer has no credential, key, domain, address, count, source tag or label field.

**The answer.** The tool takes no arguments: `{}` or none. Any other argument is refused with "resources takes no arguments", after the raise. It answers JSON `{"accounts":[{"service":"…","kind":"…","status":"exists, not connected"}]}`; an empty list is `[]`, never absent. Later sections (routes, devices) are new top-level fields in the same object. The wire type is a named struct so a reflection test pins its fields. Errors go through the plane's `guesterr.Filter` as other tool errors do. The server's own refusals are `guesterr` safe texts, so the guest sees their fixed wording, and anything else becomes the filter's reference line.

**Package shape.** `broker/resources` is pure apart from the injected functions: `Config{Plan, Raise func(machine string) error, Table *accounts.Table}`, `New(Config) (*Server, error)` (Raise and Table required), `List()`, `Call(ctx, machine, lineage, name, args)`. Imports are only the standard library, `broker/localapi` (the plan's frame), `broker/clerk/accounts` and `broker/guesterr`. No net, exec or file I/O. agentosd's wiring passes `accountsock.Gmail{...}.Plan` (or nil), a raise through its machine manager (as `questions.open` does, with the manager loaded at call time), and `accounts.Known()`.

**Considered and not chosen.** The server could be a file in `cmd/agentosd` beside `questions.go`, which needs no new package or guard lines. It is a package because PLN-7's other sections will grow it, and its tests should not need agentosd. A new mail-clerk op answering only listings would carry less across the owner socket, but every field `Plan` carries is already table wording, and the table substitution above makes the clerk's strings irrelevant. It would add a clerk change for no data saved.

### Lifecycle (integration owner: this package and its agentosd wiring)

| Stage | Outcome |
|---|---|
| Gmail signed in; plan has found, unconnected items | `resources` lists them in plan order, table wording; caller is private afterwards |
| Owner connects one (today only Gmail, through its `oauth` route) | It leaves the list on the next call (`Connected`) |
| Owner tapped Set up on an item with no route ("Listed: …") or Later | Still listed; first use asks to connect (step 8) |
| No mail account set up | `{"accounts":[]}`; caller still raised |
| agentosd started without a mail clerk (`-mail-owner` unset) | `{"accounts":[]}`; caller still raised |
| Mail clerk restarted | First call rebuilds the plan in the clerk; same list for the same mail |
| Grant death, refused sign-in, clerk unreachable or answer over bounds | Fixed refusal, no partial list; caller still raised |
| Raise fails (machine gone, label save fails) | Fixed refusal; the plan is never read |
| Public guest calls | Raised to private first; its later model calls use only private-allowed routes |

## Requirements (local IDs; SPEC §12.1 step 7, PLN-7, PLN-3, REV-5, DEV-8, CLK-1)

- **TN-account-plan-guests-1.** The `resources` tool is listed and served on every guest socket that agentosd opens. `Call` reports `handled` only for that name, and refuses any argument but an empty object.
- **TN-account-plan-guests-2.** Every call raises the calling machine to private before it reads the plan or answers. A failed raise answers the fixed refusal and never reads the plan.
- **TN-account-plan-guests-3.** The answer lists exactly the plan's items with source `mail` or `device` that are not connected and whose ID is in the shipped table, in plan order. Each carries only the table's name and kind for that ID and `accounts.NotConnected`. No string from the clerk's answer reaches the guest.
- **TN-account-plan-guests-4.** No mail clerk, or no mail account, gives an empty list. A typed reason, a clerk error, a deadline or an answer past `localapi.MaxPlanItems` gives the fixed refusal and never a partial list.
- **TN-account-plan-guests-5.** The lifecycle table holds end to end through the guest plane with a fake clerk socket.

## Acceptance tests

**Acceptance tests:**
- TN-account-plan-guests-1 `broker/resources::TestListsOneToolNamedResources`; `TestCallIgnoresOtherNames` (catches swallowing `ask` or `worker_*`); `TestRefusesArguments` (catches a later argument silently changing the answer).
- TN-account-plan-guests-2 `broker/resources::TestRaisesBeforeReading` (the fake `Plan` fails the test if called before `Raise` returned; catches raise-after-answer); `TestFailedRaiseReadsNothing` (catches answering on a failed raise); `TestRaisesOnEmptyAndRefusal` (catches skipping the raise when there is nothing to list).
- TN-account-plan-guests-3 `broker/resources::TestListsOnlyFoundUnconnectedKnown` (table cases: an `always` item, a connected item, an unknown ID and a `device` item; catches listing the card, wallet or mailbox, or a connected account); `TestWordingComesFromTable` (a fake clerk sends a canary `Name` and `Kind` for a known ID; the canary is absent and the table's wording present); `TestAnswerFieldsArePinned` (reflection on the wire type: exactly `service`, `kind`, `status`; catches a later field); `TestOrderIsPlanOrder`.
- TN-account-plan-guests-4 `broker/resources::TestNoClerkIsEmptyList`; `TestReasonErrorDeadlineAndOverBoundRefuse` (catches a partial list on any of the four).
- TN-account-plan-guests-5 `broker/cmd/agentosd::TestResourcesOnGuestSocket`: through `openGuestPlane`'s tool set and a fake `accountsock` server, one case per lifecycle row. The public-machine row checks the machine's `DataLabel` reads `private` after the call.
- Mutants, named in the PR, each failing a test above: move the raise after the read; ignore the raise's error; use the clerk's `Name`; keep `always` items; drop the `Connected` filter; answer a partial list on an over-bound answer.

## Scope

- `broker/resources/` (new): `resources.go`, `resources_test.go`, `ASSUMPTIONS.md`.
- `broker/cmd/agentosd/`: `tools.go` (`registeredTools` takes the server), `main.go` (only to build the server from the existing `pageAccounts` values and the machine manager), `tools_test.go` or a new `resources_test.go`, `ASSUMPTIONS.md`.
- This brief.

**Guard files:**
- `tools/risk_tier.py`: add `"resources"` to `TIER_A_BROKER`, under (b): it decides what private content reaches a guest.
- `broker/daemon/arc2_test.go`: add `"resources"` to `cmd/agentosd`'s import list, and a rule for `resources` itself, `{"localapi", "clerk/accounts", "guesterr"}` with `forbiddenStd`.
- `tools/g1_scope_g2.txt`: `allow broker/resources/`. That needs a one-line `exempt-pr N` companion PR under D-198, with its own Security accept.
- `tools/trusted_base_parsers.txt`: one line, `inert github.com/ghbmrk/agentos/broker/resources -- encodes the resources answer; decodes only the tool's empty arguments and agentosd's plan frame`, if `python3 tools/trusted_base.py` asks for it. `broker/resources` is not under a `tools/trusted_core.txt` root and no root links it. If the core's lines grow, stop and ask for a D-159 row.

**Out of scope:**
- PLN-7's route, clerk and device sections. The PR files one `work-item` issue per section, labelled `class:release`, each naming its missing data source.
- Any change to the mail clerk, `accountsock` or `accounts`. A gap there is a question on this issue, not a local fix.
- The guest plane (`broker/guest`) and the kernel.

## Dependencies and usage

Needs #3189 slices (a) and (b), both merged. The `cmd/agentosd` edits run in the serial agentosd chain (D-111). Open PR #3478 touches `broker/cmd/agentosd/main.go`, `broker/daemon/arc2_test.go`, `tools/risk_tier.py` and `tools/g1_scope_g2.txt`, so this build starts only after #3478 merges or closes, and only when no other open PR touches those files. If questions 1 or 2 on #3194 are answered against this design before the build starts, the brief is amended first. Estimate (a checkpoint, not a ceiling): about 70k tokens.
