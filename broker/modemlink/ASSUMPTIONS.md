# modemlink: assumptions

Started for P2-2w-d2b-s2 (#927) against CH-1 and CH-19. Each row is a reading a later change could overturn.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| ML1 | **An adoption under way lasts only while the bridge reports the same swapped or unbound SIM (#927, M7).** `setState` clears `adopted` on any report whose SIM differs or that carries none (ok, down), so the page offers the SIM the bridge now reports, never "setting up" one no longer in the modem. `Adopt` checks the tag against the SIM reported now, so a stale page cannot record a SIM pulled since. | CH-19 | If the bridge reported the adopted SIM under another state while it reopens, the clear would re-offer a SIM the owner just confirmed; the clear would then need to key on the SIM alone. |
| ML2 | **The bridge reports a SIM's serial only while the line is swapped or unbound (#927, M12), and modemlink keeps it only then.** Both ends hold the rule: the bridge's `open` returns no serial with `StateOK`, and `setState` drops an ICCID that comes with any other state. | CH-1, CH-19 | A state that needs the serial while ok (say, to show which SIM is in use) must add it to both ends and to this row. |
| ML3 | **A picture notice (CH12-mms) is counted, never inboxed, and journaled at most `InboundPerMinute` times a minute.** It is taken after the paused and second-line checks, so an owner's picture while paused is refused and retried like a text. Owner means `From` equals the owner's number and is not alphanumeric. Counts are since start and exact; past the minute's bound only the hook call is skipped, so a flood cannot fill the journal. | CH-12, OP-5 | The photo-input package fetches the picture: it adds its own path from here, and the bound and the note change with it. |
