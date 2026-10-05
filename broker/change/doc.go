// Package change is the one change pipeline (SPEC §11, CHG-1 to CHG-6, and
// ADP-4 for routing rules).
//
// Every adoptable change, whatever its source (Loop 1, the model router, an
// upstream image, a shared package), is a change to one managed tree of
// files and takes one path:
//
//	candidate → evaluate on the frozen held-out and security suites
//	          → adoption intent (journal) → activate with fallback
//	          → keep as a rollback point (Revert, Recheck)
//
// What a change is comes from the namespaces of the paths it edits and
// their content, never from the candidate's description of itself. The
// pipeline is the journal's executor for meta.change intents and supplies
// Check, which the broker's policy calls for them: it allows what the
// standing rules (CHG-6, CHG-3) cover and returns ErrNeedsOwner for the
// rest. The package uses no inference (ARC-2).
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package change
