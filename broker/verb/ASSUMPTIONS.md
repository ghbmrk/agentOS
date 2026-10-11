# Verb list and demo mismatch check: assumptions

Built for ADP-8 (PR #208). Each row is a reading of the spec, or a gap left
for a later package, that a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| V1 | The mismatch rule keys on a verb's class, not its name: any outbound demo run of a Reversible verb blocks adoption, so read, draft, organize and any reversible verb added later are covered alike. | ADP-8, ADP-2 (organize changes only what the owner sees) | A new class between Reversible and Irreversible would need its own rule in `Mismatch`. |
| V2 | An outbound run of a verb not on the list blocks (`ClassOf` reports `ok == false`). | ADP-8; `ClassOf` fails closed | None expected. |
| V3 | `DemoRun.Outbound` is trusted as given. `Mismatch` does not observe egress itself; whoever fills it in is the trust base. It must come from the demo harness's observed egress, never from the adapter's own claim. Nothing calls `Mismatch` yet. | ADP-8, A13 | Wiring, the source of `Outbound` and the end-to-end A13 test are ADP-8b. |
