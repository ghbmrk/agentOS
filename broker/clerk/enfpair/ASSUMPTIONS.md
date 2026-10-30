# Enforcer pairing helper (core side): assumptions

Each row is a reading of the spec, or a property the code relies on, that a
reviewer may want to change (briefs/ENF.md slice r, #3692, decision 10).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| ENF-r-11 | **The helper erases the caller's plaintext buffer in `Seal`, whether or not sealing succeeds,** and keeps only the envelope. It holds no private key, so nothing it keeps opens without the enforcer. Copies the pairing protocol made before handing over the buffer are that clerk's to clear (each device row, which wires the helper). | STO-3 ("never kept on the core") | — |
| ENF-r-12 | **The sealed copy lives in memory only**, until the enforcer's fingerprint read matches its hash (`Held`). A core restart in the 10 minutes before the add-device change lands loses it, and the owner pairs again; persisting it would put a copy on the core's disk for no gain in safety. | decision 10 | If restarts during setup prove common, keep it in the core's sealed store. |
| ENF-r-13 | **The link carries the device and the hash in its query and the envelope in its fragment** (`Sealed.Link`). The fragment is never sent in a request, so the envelope is in no server or proxy log; the page's script posts it back with the tap, and the page refuses it unless it hashes to the query's hash. | decision 10 | — |
