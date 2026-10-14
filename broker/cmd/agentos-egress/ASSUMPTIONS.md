# Vault process (agentos-egress): assumptions

Rows are added per package that touches this command. A reading a later spec version could change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| S2-1 | The Owner Card's entry (`recovery.CardName`) in the open vault is the only proof that a card made it. Finish's seal (`sealEnroll`) is refused with a fixed reason (428, `ErrCardRequired`, mapped to `card pending`) while that entry is absent. The page's card latch and its PeerUID-only report are not consulted. The check follows the not-confirmed check, so an unconfirmed seed still answers 409. | HW-1, A1 | A card made some other way would need its own marker. |
| S2-2 | A PIN enroll whose slot change errors with `vault.ErrSlotDecided` keeps the TPM lockout (no `giveBack`): the seal landed, so the change completes at the next open and the lockout protects it until then. `trust` then says the PC is now trusted but saving did not finish (`errHostSlotDecided`, or `errHostSlotDecidedPIN` when a boot PIN was set), not "nothing was changed". An enroll with no PIN still gives the lockout back. On the decided path the lockout returns only at the next TPM open without a PIN (`trusted.go:391-396`). | CRED-8, HW-1 | Giving the lockout back after a landed seal would leave a PIN slot unprotected by lockout; keeping it after an undecided change would block the owner. |
