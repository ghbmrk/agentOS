# W3-builder-tune: Builder per-job counters (#126)

Board section: Integration: wiring merged packages into the box.

Potency's follow-ups on #126, once builder jobs run: per-job counters (tokens, wall time, outcome) to retune 200k/30 min after 20 jobs; a STATUS line when the builder is not set up; reset Loop 1's tried mark when a job ends on an infrastructure error (admission, ErrNotClean), if the counters show such failures matter; and, if security agrees, explicit-good values in the brief. Potency on #134: once two jobs in a row end refused for lack of model grants (agentos-egress without `-builder-from`), STATUS says "Learning: the builder can't reach a model; only repeated routines are learned." (wording to UX).

**Precondition:** W3-builder-image

**Owner:** loops thread (P3-2)

**State on the board before the 2026-10-08 index split:** in review (counters, STATUS line; tried-reset waits for counts)
