// Package journal is the broker's write-ahead journal and intent engine
// (SPEC §9, OP-1 to OP-7).
//
// Every effect the broker causes goes through one lifecycle:
//
//	Submit → Authorize (authorized | denied)
//	       → Dispatch: recheck, journal "dispatched", call the executor
//	       → observed (succeeded | not_applied | unknown)
//
// The journal record for a step is durable before the step acts. In
// particular the "dispatched" record is fsynced before the executor is
// called, so after a crash the journal can only over-report what may have
// reached a service, never under-report it. Replay turns every attempt that
// was in flight into outcome_unknown, and an account with unresolved intents
// accepts no new dispatch until they are resolved by evidence (OP-2, OP-4).
//
// The package uses only the Go standard library and never needs inference
// (DEP-1). Policy (grants, budgets, approvals) and executors are supplied by
// the caller; the engine owns ordering, durability, and recovery only.
//
// A domain lifecycle (device actuation, DEV-5; credential hand-off, CRED-11)
// is a set of intent kinds declared with Lifecycle and Register, never a store
// of its own (OP-11). Callers run Lifecycle.Check before Submit, check the
// daily cap against Lifecycle.DailyCount, and build UNDO with UndoPlan; the
// guard in broker/durable fails CI for a package that persists outside the
// journal without being listed with its OP-11 kind.
//
// Assumptions that a later spec version could change are listed in
// ASSUMPTIONS.md next to this file.
package journal
