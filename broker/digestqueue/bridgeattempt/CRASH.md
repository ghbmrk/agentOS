# W5-D10 assembled crash-cut evidence

TestAssembledDigestRecoveryAcrossEveryDurableBoundary enumerates twelve cuts:
pre/post replacement at source Peek, queue admission, source Ack, queue ack bit,
queue Begin, and queue Finish. The actual pipeline, adapter, collector and queue
use independent private files. Every recovery constructs fresh components and
stores; no assertion reads the old source/queue heap. Unexpected model evaluation
fails, and the notifier is a counted local fixture with no account/carrier.

Each cut must be reached and return an error. Failed admission/begin cannot invoke
transport. Partial source acknowledgments recover exact generation/hash. Reopen
re-establishes durable state before source consumption resumes. A post-Begin
failure can conservatively remain Unknown even though the counted fixture saw no
transport call: storage uncertainty does not automatically grant a retry. A
pre-Finish failure after a call stays Unknown; a visible post-Finish replacement
can remain Accepted only after successful durable reopening. None of these states
asserts carrier delivery, owner visibility or acceptance.

After every recovery a new real pipeline notice forms generation two with a
separate batch; the earlier association/outcome remains unchanged, and another
collection adds nothing. No recovery path itself calls transport. Source receipt
privacy and actual owner/bridge handler tests are inherited from W5-D9.

The pre-replacement injection performs no store write. The post-replacement
injection returns an error after actual FileStore.Save succeeded. This models
caller uncertainty over an observed replacement; it does not simulate unsynced
directory entries, sudden power loss, storage firmware, encrypted-volume recovery,
multiple writers, live carrier faults, or timing of STOP/forget/pacing policy.
Those require separate integration and hardware evidence. Test fixture gates
remain deliberately local and unqualified. This is additional review evidence,
not project acceptance, independent threat review or production enablement.
