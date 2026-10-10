# CAP-4c: Calendar as an event source

Board section: Uncovered requirement IDs (CONV-5).

SPEC CAP-4 lists calendar among the sources that trigger work through the event bus (mail, files, calendar, web changes, timers). The bus exists (P3-3, `broker/events`); mail publishes to it, calendar has no adapter and no BOARD row (found 2026-10-10 in the assistant-boundaries review).

**Needs:** P3-3

**Gate:** lenses (calendar content is untrusted input: event titles, descriptions and invitees render as untrusted and carry labels like mail; write access, if any, is an irreversible action and asks first)

**Failure path to test first:** an invite whose description carries instructions or a code request reaches the bus as labelled untrusted data and triggers no action by itself.

**Scope:** to be set when the brief is expanded; start read-only (poll or subscribe to one calendar through the owner's account, publish create/change/cancel events with dedupe), then decide writes separately.
