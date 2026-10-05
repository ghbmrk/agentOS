# Arbitration run 2 (main @ b4962e4)

**Inputs.**
- Security review 2: `reviews/security/2026-10-05-security-review.md`. Its spec edits (RES-2, RES-4, ADP-12) are already on main.
- UX review 2: `reviews/ux/2026-10-05-ux-review.md`. Its CH-12 edits are already on main.
- Potency review 2: `reviews/potency/2026-10-05-potency-review.md` on `pkg/pot-review-vxyt7q`. Its spec edits are proposed as text only.
- Per-PR gate rulings since run 1, logged in [README](README.md). PE7 was ruled there on 2026-10-05.

**Hard constraints checked.** No proposal moves a credential toward the model or ungates an irreversible action.

## Cross-lens matrix

| Item | Potency | UX | Security | Interaction | Resolution |
|---|---|---|---|---|---|
| RES-2 pool (P2) vs RES-2 CPU/I/O/pids weights (S4) | + | 0 | 0 / + | Both edit RES-2. Potency's larger hosts add machines; security's weights keep the broker and foreground first. | Complementary. One RES-2 edit carries both: the pool is derived from the host, grows only by a core-bounded rule, and runs under the weights already on main. |
| OP-9 no silent loss (P1) vs CH-12 problem-text and STATUS rules (U1, U3) | + | + | 0 | Overlap: OP-9 restates CH-12's "say what the owner can do". | OP-9 cites CH-12 for wording instead of restating it. OP-9 lines are CH-12 exception lines. Owner choices are "what the owner set", so they are not STATUS exceptions, which matches OP-9's "named once, listed in the digest". |
| UPD-9 held security fixes (P3) vs PE7 sleep window | + | 0 / + | + | Both claim the quiet window. | A staged security fix takes the window first. PE7 does not start a sleep on a night a fix is due to apply. UPD-6 (never during accepted work) is unchanged. |
| CAP-3 rebuild before remove (P5) vs forget and value store (#119, step 3b ruling) | + | + | 0 | A rebuild could reuse cached values from the forgotten record. | Rebuild under the #109 rules: explicit-good anchors only, content allow-list. The forgotten record's values and HMAC hashes are deleted before the rebuild. Mark's open CAP-3 decision (PR1, source deletions) is untouched. |
| CAP-5 "Keep it as a skill?" (P4) vs #109 ruling part 3 | + | 0 | 0 | Same mechanism. | Adopt it, with the YES bound to the shape hash and the representative run shown (lesson from #76), paced by CH-15. |
| S1 recipient text rendered as "N recipients, see the Wi-Fi page" | 0 | - (small) | + | Wording must follow U2's single name. | Use the CH-12 name once the voice rule sets it. No conflict. |
| PE7 (P6) | + | - (small) | 0 / + | Already arbitrated (README, PE7 final). | No change. |

There are no forks for Mark. Every row is auto-decided, because no lens gets meaningfully worse.

## Spec diff for the next L1 PR

The spec diff needs Mark's "yes" in the thread that commits it. It folds in potency's proposed text with these changes:

1. **OP-9:** as proposed, but replace "in one owner-worded line with what would fix it" with "in one line worded per CH-12".
2. **RES-2:** potency's sentence, appended after the CPU, I/O and process clause already on main.
3. **UPD-9:** as proposed, adding: "A security fix due in the quiet window takes precedence over learning work there (PE7)."
4. **CAP-3:** potency's text, adding: "The rebuild uses only the remaining evidence; values and hashes kept from the deleted record are removed first."
5. **CAP-5:** potency's text, with "a yes, bound to the routine shown, is an owner outcome for CHG-1."
6. **A2 and A11:** as proposed.
7. **Carried from security:** the CH-20 [Risk] wording (run 3).
8. **Carried from earlier runs:**
   - CRED-8 pending-key wording;
   - UPD-8 and A14 offline root expiry (now on main; check);
   - the CH-3/CHG-6 note.

## Steering

- **Potency:** the per-PR gate already rules most items; keep sending designs before building, as was done for PE5 and PE7.
- **Security:** route the code fixes for findings 1–4 to BOARD first; they block nothing else.
- **UX:** take the local-UI rename after the voice rule lands.
- **All lenses:** decide yourselves whenever no lens gets meaningfully worse. Only real trade-offs go to Mark, via the coordinator.
