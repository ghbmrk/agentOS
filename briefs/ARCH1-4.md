# ARCH1-4: Simple text/call outcomes over composed capabilities

**Owner:** primary coordinator routes to existing owners; unclaimed advisory extension.
**Class:** release design/acceptance extension. **Requirements / gates:** CH-2–5/8/10–21, ONB-3/8/9, CAP-6/9/10/12/13, CRED-11, OP-2/6/7, RES-1–4; A1/A4/A13/A14.
**Needs:** ARCH1-2/3, POT-P1/P2, W3-goal/W5/W9, CH-21e, P2-3/S2/PE7-call, existing CH-20w/output integration and UX3/UX4 proposals.
**Record:** [Simple-interface review](../reviews/combined/2026-10-08-simple-interface-review.md), source `a52a678a4f4d854eaf737ffaa8c3777781efea56`.

## Scope and ownership

Extend existing integration, owner-channel, task-lifecycle and usability acceptance. The owner requests outcomes through text/call; the OS absorbs source joins, credential mechanics, eligible compute routing, retries and bookkeeping. Material authority, disclosure, cost, uncertainty and recovery limits remain explicit. Broad authorized private context and automatic in-policy choices remain strengths.

This is intake, not a new runtime framework or parallel authority store. Existing UX3/UX4 findings retain their identifiers and owners; their draft fixes are not assumed merged. CH-20p/a/m retain their existing later status. This brief does not adopt new control grammar, hands-free approval, grant semantics, authentication factors, global preferences or a remote UI. Such changes need L1; implementing existing requirements does not.

## Acceptance

1. Reuse POT-P1/W3-goal/ARCH1-2 task, intent, artifact and journal state for one truthful outcome view across text, call, lock/unlock, correction and restart. Hide internal handles except where a short identifier is needed to distinguish a decision. Agent summaries cannot certify recipients, select authority or convert transport acknowledgment into completion.
2. Continue safe, useful branches within established grants while an independent effect waits. Automatically select qualified routes/hosts within accepted data recipients, credential mode, reserves and caps. A resource inventory is not a mandatory owner dashboard. Ask only material ambiguities or outcome tradeoffs; preference answers/defaults cannot authorize effects or increase bounds.
3. Render verified consequential facts and exact valid reply/proof at each required decision. Preserve canonical recipients, payload/amount, reversibility, expiry and batch-item visibility. Keep agent text distinguishable; finish existing CH-21e code-request/reply-grammar protection. No extra approvals for already-permitted source joins or routine eligible fallback.
4. Extend existing P2-3/S2/PE7-call integration to the qualified owner call path. Speech remains chat; keypad remains broker proof/control under CH-5/17. Bind concurrent request selection, isolate keypad material, and support the specified text fallback when keypad use is unavailable. Qualify real carrier/modem behavior separately from synthetic DTMF tests. Do not advertise spoken STOP or a spoken code as authoritative.
5. Keep model-independent STOP/STATUS and existing restrictive controls available. Translate technical failures into the affected outcome and a next step that works. Preserve pending/unknown/partial outcomes and actual undo limits. A dropped call or message does not supply consent, silently cancel approved work, or make uncertain effects safe to repeat.
6. Deliver usable native artifacts to an already-authorized destination and support version-aware correction. Distinguish prepared, delivered, observed and owner-accepted states. Cover outages, withheld content, revoked destinations and undelivered notices. Do not require copying multipart text or a local trip as the normal successful remote-task completion path; do not broaden disclosure to avoid one.
7. Exercise questions, approvals and notices under shared pacing and quiet-hours policy, including model failure and restart. Preserve CH-15's daily health digest. Explain required local setup/new-authority/recovery steps plainly without promising they are remotely bypassable. Reuse UX3 setup/status/recovery and UX4 first-result/full-journey cases.
8. Freeze matched task and owner-effort targets before INT-A/H6 qualification. Include at least two private sources, a usable artifact and a second authorized output from ARCH1-3, with text/call switches and repeated work. Count quality, active owner minutes, interruptions, repeated context, technical choices, setup, maintenance, correction and recovery. Measure comprehension of consequence/recipient/uncertainty and ability to restrict authority. Zero unauthorized effects/code leakage and truthful completion are invariants, not weighted convenience scores.
9. Negative replay covers duplicate/delayed messages, ambiguous “yes,” multiple tasks and approvals, changed recipient, expiry, stale codes, spoken code/STOP, partial or repeated DTMF, disconnect during proof, secret-shaped output, lost acknowledgment and models down. Prove existing authority and task bindings survive; unsupported calls/hardware remain explicitly unqualified.

## Delivery and estimate

Primary splits implementation in existing lanes; this advisory PR only registers acceptance and dependencies. INT-A/H6 own assembled evidence; W5/CH-21e own owner-channel integration; POT-P1/W3-goal own lifecycle; P2-3/S2/PE7-call own call qualification; CH-20w/CRED-11 and chosen adapters own delivery. UX3/UX4 carry prior defects without duplicate filings.

Proposed checkpoint: 20k tokens for the first bounded integration/acceptance slice, not a ceiling. Runtime, hardware and owner studies require their own scoped claims and evidence. No measured UX or productivity gain is claimed here.
