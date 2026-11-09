# Byte caps' composer (core side): assumptions

Each row is a reading of the spec, or a property the code relies on, that a
reviewer may want to change (#4578, NET-2 Byte caps, D-248).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| NET-2-cap-sizing-1 | **A cap is exactly its stated figure**: the daily bytes the destination's declaration states (CLK-14), the signed image's figure for the kernel's own destinations, or a backup target's next full backup's size (`backup.Size`); the edge's one cap is its declared total. No margin is added, since NET-2 sizes a cap from what is stated and a margin would be an invented figure. | NET-2 Byte caps | If legitimate days trip, the declaration states a larger figure; a margin is a spec change. |
| NET-2-cap-sizing-2 | **No figure, no signing**: a destination, or the edge, stating no daily bytes is refused with `*NoDailyBytes`, naming it in printable ASCII in owner wording, and no link is drawn. A silent default would trip the core later or let a leak pass under it. | NET-2 Byte caps | — |
| NET-2-cap-sizing-3 | **`Inputs` is the core's whole list**: `Propose` replaces the destinations, caps, bases and edge cap of the policy in force and keeps every other field; a destination left out is dropped, which fails safe (the core stops reaching it). Each cap's basis is signed in the document (`policy.Document.Basis`), so the enforcer's page names it from what the owner signs, never from link text. | NET-2 The core's list, NET-4 Loosening | — |
| NET-2-cap-sizing-4 | **The seam is frozen for its one caller, cmd/agentosd** (sub B's call-site row): `Basis`, `Dest`, `Inputs`, `Figure`, `Propose`, `Next.Link(name)`, `Next.Figures` and `ErrNoDailyBytes`. `Link` takes the enforcer's name, as `action.TighteningLink` does. Sizing lives here, not in `policy`, since the enforcer never sizes a cap: it only enforces the signed one. Where the declared figures and the image's figure come from is the caller's: no CLK-14 declaration struct carries daily bytes yet. | CLK-14, KRN-12 | — |
