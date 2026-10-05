# Event bus: assumptions

Built against SPEC v0.12 (CAP-4, CAP-3, REV-5, CRED-1, CH-13, CH-15) and
DECISIONS D1.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| E1 | Sources (mail, file, calendar and web watchers, adapters) publish events with a `ref` and a `version`; the bus delivers each (kind, account, ref, version) once. A web-change watcher publishes the page's content hash as the version, so only a change causes work. Watchers themselves come with their adapters (§10A). | CAP-4 | None here. |
| E2 | Triggers are broker-side and registered at start. Delivery is at-least-once per (event, trigger), with a stable key for idempotent work; after `MaxAttempts` (default 5) the delivery stops and the digest says so. A trigger that panics counts as a failure. | CAP-4, OP-1 | Add backoff between attempts if a slow source needs it. Small. |
| E3 | Event content is owner data (REV-5 lists "event-bus content"). Mail, file and calendar events are private whatever is declared; web and timer events are private unless declared public; a timer's text is task text (D1). The machine that receives an event's content gets its label; the trigger that starts the work binds that. | REV-5, D1 | None expected. |
| E4 | Missed timer firings during downtime coalesce into one event for the latest due time, rather than a burst. | CAP-4 | Fire each missed time instead. Small. |
| E5 | Interrupts: only an irreversible decision can interrupt, and only when the owner marked its class urgent; other irreversible decisions are batched (CH-13) with the digest; everything else (events, results, failures) is a digest line. Pacing and quiet hours (CH-15) stay with the owner channel downstream. | CAP-4, CH-13, CH-15 | None expected. |
| E6 | A settled event keeps only its ID (for dedupe); its content leaves memory at once and the store at the next compaction (when settled records outnumber live ones, and on every `Forget`). A deletion in recall drops every event about that source, pending deliveries included, and keeps the ID so the item is not delivered again. The dedupe set is unbounded for now. | CAP-3, RES-4 | Expire old IDs by age. Small. |
| E7 | Summaries, bodies and refs are scrubbed with the recall scrubber before storage (recall R4). | CRED-1 | None here. |
