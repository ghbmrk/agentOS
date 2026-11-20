# Control: assumptions

Each row is a reading of the spec, or a gap left for a later package, that a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| CTL-owner-text-lost-1 | **Owner text the agent cannot take is dropped, not held.** When `Agent.Deliver` fails (at boot or restart the agent's machine has no open services, `guest: machine has no open services`), task chat and reaction events get one fixed reply saying the message was not received and to send it again once the agent is back, with STATUS naming why it is down. Nothing is queued, so there is no bound, no store across restarts (REV-5 label) and no rule for a late message the owner has since changed their mind about. | CH-2, CH-12 ("every text that reports a problem says what the owner can do"), #5429 option 1 | If owners often text in the window, a queue row (#5429 option 2) adds a bounded, labelled hold in `broker/guest` and replaces this reply. |
