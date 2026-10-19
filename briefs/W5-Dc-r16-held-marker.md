# W5-Dc-r16-held-marker: a released held text says it waited

Board section: Integration. Work item: #987 (the STATUS half shipped in W5-Dc-r1b, #652). **Tier A** (`broker/owner`). Serves CH-15, CH-12. Edits `pacer.go`: do not run beside CAP3-held-forget-scope (D-111).

**Why / failure path.** `packHeld` (`pacer.go:638`) drops `HeldText.At`, so an update held from 23:00 reads as current when released at 07:00 (agentosd ASSUMPTIONS PW4). The owner acts on stale news.

**Requirements:**
- W5-Dc-r16-1: a released text that waited past a set threshold (default: the text was held, so any held release) carries a short marker with its original local time, e.g. "(from 23:00)", fitted inside `control.MaxText` and never cut off the text itself.
- W5-Dc-r16-2: agent text keeps going alone and keeps `control.FitAgent`; the marker is added by the broker, never inside the agent's text, so an agent cannot forge or suppress it (CH-19).
- W5-Dc-r16-3: the marker uses the owner's box-local time (`c.cfg.Location`), not UTC.

**Acceptance tests:** (REQ: W5-Dc-r16-1..3)
- `broker/owner/pacer_test.go::TestReleasedHeldTextCarriesItsHeldTime` (-1; mutant: no marker).
- `::TestHeldMarkerIsBrokerAddedForAgentText` (-2; mutant: marker inside the agent text, which a crafted "(from ...)" in agent text must not stand in for).
- `::TestHeldMarkerUsesBoxLocalTime` (-3; mutant: UTC).

**Open point for the builder.** Whether a text held for seconds (rate pacing, not quiet hours) also gets the marker: pick "only when held across a minute boundary of local time or longer than 5 minutes", note it in `ASSUMPTIONS.md` PW4, and keep it one constant.

**Out of scope.** #988 (forget reach into the hold): `ForgetRecent` already drops held agent texts; its remaining scope bug is CAP3-held-forget-scope.

**Scope:** `broker/owner/pacer.go`, `pacer_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md` (PW4), this brief.

**Usage estimate:** 50k tokens; checkpoint at 40k.
