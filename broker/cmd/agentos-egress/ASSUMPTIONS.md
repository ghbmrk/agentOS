# Vault process (agentos-egress): assumptions

Rows are added per package that touches this command. A reading a later spec version could change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| S2-1 | The Owner Card's entry (`recovery.CardName`) in the open vault is the only proof that a card made it. Finish's seal (`sealEnroll`) is refused with a fixed reason (428, `ErrCardRequired`, mapped to `card pending`) while that entry is absent. The page's card latch and its PeerUID-only report are not consulted. The check follows the not-confirmed check, so an unconfirmed seed still answers 409. | HW-1, A1 | A card made some other way would need its own marker. |
