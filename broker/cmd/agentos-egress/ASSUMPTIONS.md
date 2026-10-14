# Vault process (agentos-egress): assumptions

Rows are added per package that touches this command. A reading a later spec version could change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| S2-1 | The Owner Card's entry (`recovery.CardName`) in the open vault is the only proof that a card made it. Finish's seal (`sealEnroll`) is refused with a fixed reason (428, `ErrCardRequired`, mapped to `card pending`) while that entry is absent. The page's card latch and its PeerUID-only report are not consulted. The check follows the not-confirmed check, so an unconfirmed seed still answers 409. | HW-1, A1 | A card made some other way would need its own marker. |
| S2-2 | A PIN enroll whose slot change errors with `vault.ErrSlotDecided` keeps the TPM lockout (no `giveBack`): the seal landed, so the change completes at the next open and the lockout is what protects it. `trust` then tells the owner channel the PC is trusted (saving not finished) and answers that it is trusted but not yet saved, with the step (trust again, which replaces the slot for this TPM), not "nothing was changed". A decided enroll with no PIN keeps the lockout state it had (the give-back runs only on success). | CRED-8, CRED-9, HW-1 | A slot change that can be undone after the seal would make the kept lockout and the notice wrong. |
