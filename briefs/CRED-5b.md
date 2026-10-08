# CRED-5b: Build and test broker-held route failure, fallback and owner pause

Board section: Phase 0: harness and risk spikes.

Source: the CRED-5f, CRED-5t and CRED-5w spec-diff (#421). Once plan-route code exists in `broker/` (CAP-11, the S8 build rows), implement and test the CRED-5 clauses that spec-diff added:

- **Failure triggers (CRED-5t, tier A: egress, vault).** A refresh or other response the egress proxy cannot match to a declared shape falls the route back; an unmatched refresh response is dropped, never forwarded to the CLI. Qualification test: a synthetic canary token in an undeclared refresh response shape never reaches the worker (CRED-1). A refused login stops plan-route attempts and tells the owner; no retry until the owner resumes.
- **No API key (CRED-5f).** With the plan route withdrawn and no API key granted, routing goes to another granted route and the owner is told (CAP-9, ONB-9). #420 implements the skip (`broker/route` `Config.Withdrawn`, `RouteWithdrawn`). Two checks (#421 L3 point 4): withdrawal must key on the route kind or the route, not the provider name, or withdrawing a plan also drops that provider's API key route (plan routes need a distinct Provider, R1); and the notice is one STATUS line plus one digest line per withdrawal, never a text and never repeated daily (ONB-9). Owner pause, consent withdrawal and the runtime failure triggers use the same skip hook.
- **Pause and withdrawal (CRED-5w).** The broker-held pause/resume control words (CH-11) and the Wi-Fi page control; pause needs no code, resume a low-tier code, and resuming an unconfirmed route asks consent again. A withdrawing release and a prohibition security notice each produce one STATUS and digest line per affected owner (UPD-4 pinned boxes included).

- **From #426 (CRED-5t release findings).** Relay plumbing: refresh-token injection, a transactional vault Swapper, and the plan adapter. Wire `RouteFailed`/`Resume` to the owner notice and to CAP-9; the owner resume path reopens only a refused-login stop, never an unmatched-response stop.

The failure-trigger part is tier A; split it into its own package if the brief's estimate would pass 150k.

**Requirements:** CRED-5, CRED-1, CAP-9, CH-11, ADP-10, UPD-4

**Needs:** #421 merged; CRED-5c (before the resume and re-consent item); CAP-11 plan-route code (S8 build rows)
