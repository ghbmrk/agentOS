# One guarded digest attempt — unenabled implementation candidate

This package joins durable Queue.Begin/Finish to owner.Channel.InformContext.
It makes at most one transport call for an acknowledged Ready batch. Queue.Begin
persists Sending before that call; restart turns unresolved Sending into Unknown.
A failed Begin never sends. Failed Finish quarantines storage; reopening does not
replay a possibly sent text. Transport acceptance is neither carrier delivery nor
owner visibility, an owner verdict, implicit acceptance or effect success.

A closed trusted source allowlist, current source validators, fresh policy gate,
clock, queue and owner notifier are required. Configuration and callback inputs
are copied; callbacks cannot mutate the rendered text or private queue state.
The instance serializes its own attempts with a context-aware semaphore. A
cancelled waiter returns without waiting for a busy transport. Use one coordinator
for the queue; this is not cross-process locking or containment serialization.

The complete owner text is `Daily update: ` followed by every source line in
canonical queue order, separated by a space. Receipts, hashes and references are
never texted. If Disclose or Fit would change the complete text, sending refuses
before Begin. Long batches, secrets, unsupported characters and embedded control
characters remain queued and require an explicit reviewed rendering/segmentation
policy. Nothing silently truncates lines or marks a pointer as delivery of all
source content. Rendering eligibility does not authenticate a producer or make
untrusted agent/question text into fixed broker wording.

A nil notifier result records a local `bridge-accepted` observation reference.
Only a direct SendCanceledError, with a standard cancellation/deadline cause and
Handed=false, records affirmative pre-handoff NotSent and permits the queue's
bounded attempts. The configured notifier must be the trusted owner/bridge path:
an arbitrary notifier cannot mint this proof. Wrapped/joined or malformed
cancellation, modem.ErrDown, timeout and post-handoff cancellation remain Unknown.
Late receipts do not silently settle an old Unknown batch or authorize a new ID.
Observation references identify the exact batch/attempt; they are not authenticated
carrier receipts. The bridge's sent handler still needs external qualification.

The mandatory Gate is an integration seam, not an implemented policy. The broker
must guard this entire Send scope against STOP/forget/current-source changes,
cancel in-flight transport on containment, and serialize shared pacing/priority
reservations. The gate must freshly check STOP, quiet hours, cadence, shared budget,
priority, authority and resource admission immediately before Begin. No callback
alone makes this atomic. Source issuance validation alone is also insufficient:
changesource.Validate does not complete queued/backup/transport forget reach or
live UNDO/MORE validity. A future integration must enforce those constraints and
preserve unknown-send recovery before announcing deletion complete.

No timer, daemon, default gate, new authority, live account or sender wiring is
introduced. Daily empty-status wording, multi-text associations, owner pacing,
private encrypted-state inventory, full forget reach and carrier/hardware trials
remain separate review packages. Tests assemble the actual pipeline, collector,
owner channel and local bridge handlers with independently reopened queue files;
their permissive fixture gate does not qualify real containment or deployment.
Strongest independent broker/security review and threat check remain required.
