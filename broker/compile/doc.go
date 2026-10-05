// Package compile turns successful trajectories into procedures and
// compiled skills (SPEC CAP-5), and measures what compiled skills save
// (A10).
//
// A trajectory is the effects of one task, read from the journal: the
// intents sharing a goal, in submission order. It is successful when every
// effect succeeded, the owner judged the task good (an OP-7 verdict whose
// source is the owner), and nobody judged any of it wrong. The compiler
// reads only tasks behind the change pipeline's dev split (CHG-1), so a
// skill is never built from a case that will judge it.
//
// A task seen once becomes a procedure: its steps with every value a typed
// input. Once MinRuns tasks share a shape (the same accounts, actions, and
// parameter structure), they compile into a skill: values equal in every
// run become literals, the rest become typed inputs, and the input types
// and bounds are the assumptions the runner checks (package skill). Both
// are change-pipeline candidates (§11); nothing here adopts or runs
// anything. The package uses no inference (ARC-2).
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package compile
