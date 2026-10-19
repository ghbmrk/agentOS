# W5-Dc-r16-held-marker: a released held text says it waited

Board section: Integration. Work item: #987 (the STATUS half shipped in W5-Dc-r1b, #652). **Tier A** (`broker/owner`). Serves CH-15, CH-12. Edits `pacer.go`: do not run beside CAP3-held-forget-scope (D-111).

**Why / failure path.** `packHeld` (`pacer.go:638`) drops `HeldText.At`, so an update held from 23:00 reads as current when released at 07:00 (agentosd ASSUMPTIONS PW4). The owner acts on stale news.

**Decision in this brief.** Agent texts get no marker: CH-15 forbids combining an agent text with another text and CH-12 forbids placing it inside a broker template, so the marker applies only to broker-originated held texts (status and notices). Record this in PW4. Any held release of such a text gets the marker; there is no minute or 5-minute threshold (no arbitrary caps).

**Requirements:**
- W5-Dc-r16-1: every released held broker text carries a short marker with its original local time, e.g. "(from 23:00)", fitted inside `control.MaxText` and never cutting off the text itself.
- W5-Dc-r16-2: agent text keeps going alone, unmarked, and keeps `control.FitAgent`; a crafted "(from ...)" in agent text is not a marker and is not stripped.
- W5-Dc-r16-3: the marker uses the owner's box-local time (`c.cfg.Location`), not UTC or `time.Local`. `packHeld` is a free function, so its signature changes to take the location.

**Acceptance tests:** (REQ: W5-Dc-r16-1..3)
- `broker/owner/pacer_test.go::TestReleasedHeldTextCarriesItsHeldTime` (-1; mutant: no marker; mutant: marker only past a threshold).
- `::TestHeldAgentTextIsReleasedUnmarked` (-2; mutant: marker added to or merged with the agent text).
- `::TestHeldMarkerUsesBoxLocalTime` (-3; mutant: UTC or `time.Local`).

**Out of scope.** #988 (forget reach into the hold): `ForgetRecent` already drops held agent texts; its remaining scope bug is CAP3-held-forget-scope.

**Scope:** `broker/owner/pacer.go`, `pacer_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md` (PW4), this brief.

**Usage estimate:** 50k tokens; checkpoint at 40k.
