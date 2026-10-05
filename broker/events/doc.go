// Package events is the broker's event bus (SPEC CAP-4).
//
// Sources (mail, files, calendar, web changes, timers) publish events;
// triggers start work on them. The bus is durable: an event is journaled
// before Publish returns, each (event, trigger) delivery is retried until it
// succeeds or runs out of tries, and both survive a restart. Each (kind,
// account, ref, version) is delivered once, so a watcher may republish
// freely and only a change causes work.
//
// Information flow (REV-5): event-bus content is owner data. Mail, file and
// calendar events are private whatever the publisher declares; web and timer
// events are private unless declared public (D1: task text, including a
// timer's, is private unless the owner marked it PUBLIC). Summaries, bodies
// and refs are scrubbed of credentials before they are stored (CRED-1).
// Deletion propagates from the recall index through ForgetSource.
//
// Attention applies CAP-4's interruption rule: only irreversible decisions
// interrupt the owner, batched into the digest unless urgent.
//
// Standard library only; no inference (DEP-1). Assumptions are listed in
// ASSUMPTIONS.md next to this file.
package events
