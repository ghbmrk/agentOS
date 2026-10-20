# Capability kernel: assumptions

Built for MIG-2 (#2525, D-139 step 2). Covers `broker/kernel`, `broker/kernel/key` and `broker/clerk`. Each row is a reading a reviewer may want to change.

| ID | Assumption | Spec basis | If it changes |
|---|---|---|---|
| MIG-2-a | **The owner's passkey is modelled with ed25519.** Real passkeys sign WebAuthn assertions; the verifier is the only part that differs. | KEY-4 | Swap `key.Verify`'s root check; the chain format stays. |
| MIG-2-b | **Owner-channel authentication is outside the kernel.** `Issue`, `Revoke`, `Pause`, `Stop`, `Resume`, `Cancel`, `Undo` record owner events as given; the daemon authenticates the owner before calling them. Owner-issued roots count only once they are in the log. | KEY-4 | A kernel that verifies owner events needs a signed event envelope. |
| MIG-2-c | **Verb tiers are a closed table of 16 verbs** in `key/verbs.go`; each is reversible or irreversible. Only irreversible verbs are held. | KRN-4 | A new verb is a new table row and a test. |
| MIG-2-d | **The hold window is whatever the key sets.** A key with no hold caveat has no hold; the kernel adds no floor. The first approval tap issues the standing key, so the owner's choice is the policy. | KEY-8 | A floor would be one clamp in `Limits.Window`. |
| MIG-2-e | **Novelty is the shape of a step**: verb, clerk, content class, sorted argument names and sorted labels, not the recipient. A shape completed once under a root is no longer novel under it. | KEY-8 | Add the recipient to `Shape` for a stricter rule. |
| MIG-2-f | **A duplicate fingerprint (irreversible verb) within 24 hours under one root is refused.** The fingerprint includes the recipient. | KRN-8 | The window is one constant. |
| MIG-2-g | **A plan is checked whole at accept, cumulatively, and each step again at dispatch.** Uses are charged at the first dispatch attempt only, so a redo is not charged twice and an accepted step the cap later refuses is cancelled. | KRN-5, KEY-2 | Charging at accept would reserve budget for steps that never run. |
| MIG-2-h | **Pause waits; any other refusal, including STOP, cancels the step.** | KRN-7 | none |
| MIG-2-i | **An unknown result is probed every 60 s, up to 10 checks, then parked.** At boot, a step in flight becomes `unknown` ("restart"), so nothing repeats on a guess. | KRN-8 | The probe interval and limit are constants. |
| MIG-2-j | **The unconfirmed tail is only widening entries.** At open, trailing `resume`, `key.issued` and `key.resumed` entries no anchor covers are dropped; dispatch, result and narrowing entries are always kept. | LOG-2, KRN-7 | An anchor that lags a narrowing is harmless; one that lags a dispatch would repeat an effect. |
| MIG-2-k | **Erase and per-subject keys are deferred.** The log is one AES-256-GCM key; erasing a subject needs per-subject keys, a later row. | LOG-1 | Entry bodies would be sealed per subject. |
| MIG-2-l | **`Undo` marks only.** It records that a reversible step should be reversed; the clerk reverses it as a new step the key must allow. | KRN-5 | none |
| MIG-2-m | **The plan format is frozen as `Plan{ID, Key, Steps}`**, a thin typed list (max 64 steps), per Mark's PLN-5 approval. | PLN-5 | A new field is a new entry version. |
| MIG-2-n | **`key` is a pure value library, not a core package.** It holds no state and writes nothing; `kernel` and `clerk` are core. | CLK-2 | none |
| MIG-2-o | **The mail clerk is a synthetic mailbox.** No real account is touched; the real Gmail clerk is the slice (#2526). | CLK-2 | none |
| MIG-2-p | **Submit normalizes every step.** Argument sources are forced to planner, the task is the plan id, the recipient is the `to` argument and the amount the `amount` argument (non-numeric or negative becomes -1). Content and labels stay claims. | KEY-2, CLK-2 | A planner step cannot attest its own provenance. |
| MIG-2-q | **Claims are validated only by a clerk with `Facts`.** The mail clerk here takes them as given when `Facts` is nil; the real clerk (#2526) sets it. | KEY-2, CLK-2 | A planner lies about content or labels to a clerk without Facts. |
| MIG-2-r | **A key with bounded arguments refuses planner steps by construction**, since every normalized argument is planner-sourced. An owner or clerk sourcing path is a later row. | KEY-2 | A bounded-arg key cannot yet be used until that path exists. |
| MIG-2-s | **A cancelled plan keeps probing an unknown step, and `repeats` counts in-flight, unknown and parked steps of any plan**, so a cancel cannot hide an effect that may have happened. | KRN-8 | none |
| MIG-2-t | **The duplicate fingerprint is `verb\|clerk\|args`.** Extra arguments change it; a clerk that ignores them can be evaded. | KRN-8 | Plan with an inert extra argument to repeat an irreversible effect. |
