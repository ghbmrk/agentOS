# ADP-2 amendment: the organize verb

Found during the potency lens review of PR #27 (grants). Archive, label, move and mark-read could only map to change-account, which is irreversible. So inbox triage, a core job, prompted on every action unless the owner had written a pre-allowance for that operation.

Mark decided (project chat, 2026-10-05): "Yes - reversible".

## What changes

`organize` becomes a reversible verb, like draft. It covers changes inside the owner's own account that only the owner sees and that fully undo there. An operation qualifies only if its adapter also declares the inverse operation, and the broker journals the prior state with each one. Delete, trash, filters, forwarding and sharing stay irreversible.

## Guards

| Guard | Why |
|---|---|
| Items matching security-alert patterns still ask | A hijacked agent could otherwise hide a fraud or sign-in alert. |
| At most 200 organize effects per account per day (owner-set) | Bounds a mass hide. |
| Every effect is journaled and counted in the digest, with one `UNDO` for the day | The owner sees what was tidied and can reverse it in one reply. |

## Revisions after L3 review

- **Day-wide `UNDO`.** It restores only items whose current state still matches what the agent set, and reports the ones it skipped.
- **Allowed targets.** Moves and labels go only to system states, folders the owner confirmed when granting, or `AgentOS/`. Trash, spam and folders with a retention policy are never targets. A shared or watched target counts as share, and reporting spam counts as delete-remote or share.
- **Alert guard.** Alerts are recognised first by sender, not by wording: the provider's security senders and senders the owner holds an account with or marked as financial or identity, each after a DMARC pass. Phrase patterns are a second net, in the owner's languages. The guard applies only to operations that hide a message (archive, move out of the inbox, mark read); labelling an alert still runs and is listed in the digest (arbitrator).
- **Recommended items, adopted.**
  - Per-item undo through `MORE` and `UNDO <id> 3 7`.
  - The digest names the senders most affected and lists guard hits.
  - Every organized item gets an `AgentOS` label.
  - `UNDO` ids last 7 days.
  - Anything over the daily bound is asked once, as a batch.

## Tradeoffs

| Potency | Security | UX |
|---|---|---|
| ++ Triage runs unattended | − An agent can still hide an item that matches no alert pattern, until the digest arrives | + Far fewer texts |

## Build note

`broker/verb` (PR #27, GR1) needs the new verb and its class once this merges. A verb-list change normally needs an owner-approved intent (OP-5, CHG-2); Mark's decision is that approval.
