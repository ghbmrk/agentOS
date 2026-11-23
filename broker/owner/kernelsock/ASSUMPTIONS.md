# kernelsock: assumptions

agentosd's client of the kernel's owner socket (MIG-4-run start-up slice, #2682). Each row is a reading a reviewer may want to change.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| KEY-9-named-utf8 | **An erase by name sends only valid UTF-8 (#6322).** `kernelsock.Owner.Named` refuses a label that is not valid UTF-8 with `kernel.ErrLabel` before dialing, so agentosd's forget flow gets an error rather than a match, and the kernel never sees a U+FFFD stand-in. | LOG-4 | Rests on `encoding/json` replacing invalid bytes with U+FFFD on marshal; a wire that kept raw bytes would let the kernel refuse instead. |
