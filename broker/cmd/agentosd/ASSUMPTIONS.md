# agentosd wiring: assumptions

Started by W3-forget-b2c (owed take-backs for FORGET's item 2, the UX
release finding R-1/R-2 on #327). Each row is a reading of the spec, or a
gap left for a later package, that a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| 1 | An approved item 2 that cannot be taken back now (no agent machine, recall off, or the take-back not saved) is owed: its journal outcome is Succeeded, and `resumeAgent` takes it back at a later open of recall once recall has not recorded it (`Handled`). The journal never prunes Succeeded intents. | CAP-3 (the owner's approved deletion is carried out), CH-12 | If the journal ever prunes Succeeded intents, owed take-backs need their own durable record. |
| 2 | A take-back error that is not `ErrCarried` or `ErrNotOpen` means recall recorded nothing and reset nothing (`Reach.TakeBack` wraps every failure after `MarkTakeBack` in `ErrCarried`), so trying it again cannot repeat a take-back (#327 L3 blocker 1). | CAP-3 | If `Reach.TakeBack` can fail unwrapped after resetting, `carryAgent` must stop retrying on that error. |
| 3 | STATUS's agent line says why the agent is not running, so "Send STATUS to see why." is a real step for the no-agent text. Recall off (no recall directory or vault verifier) has no STATUS line and no step the owner can reach, so that text names none and says what remains. | CH-12 (a problem text says what the owner can do; never a step that cannot fix the cause) | If STATUS gains a recall-off line, that text can name it. |
| 4 | A not-saved take-back is tried again in this boot with the forget's backoff (2 s doubling to `forgetRetryMax`) until it is saved or the box shuts down; the owner is told once at the start and once when done, matching item 1's not-saved promise. | CH-12, UX-182-3 (a promised text comes) | If retries should be bounded, the text must stop saying "I keep trying". |
| 5 | An owed take-back is not added to the forget log until it is done, so a backup restored while it is owed does not carry it. | W3-forget-b1 (forget log) | Later: log owed take-backs too. |
