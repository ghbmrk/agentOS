// Package loops is the spare-capacity scheduler shared by the three
// autonomous loops (SPEC §11A, LOOP-0 to LOOP-3) and Loop 1, the
// self-improvement loop (LOOP-4 to LOOP-6).
//
// The scheduler runs one unit of loop work at a time, only while the box
// has spare capacity: nothing in the foreground or accepted classes needs
// it (RES-1), STOP is not in force, the owner has the loop on (LOOP-0), and
// the spare AI budget has room (LOOP-2). Work yields when foreground work
// arrives: Preempt cancels it and waits at most the frozen preemption
// target, and the preempted unit is offered again later. Spare capacity is
// split across loops by measured return, value per unit of cost (LOOP-3);
// a loop that stops producing value gets less, and when no loop has
// worthwhile work the scheduler sleeps until something new arrives.
//
// Loop model calls (counterfactual replay, the clean-room builder, Loop 1's
// candidate builder) are metered against one dedicated meter, the spare
// budget, separate from every work budget (LOOP-2, OP-8). Its cap is an
// owner setting, changed only by an owner-origin intent; nothing a loop
// runs can raise it (LOOP-6, CHG-2).
//
// Loop 1 mines the journal for failures, owner corrections, slow or
// expensive steps, and repeated trajectories (LOOP-4), has a builder turn
// each into a candidate from the dev split only, and sends every candidate
// through the change pipeline (§11, LOOP-6). Owner outcomes become the
// pipeline's held-out cases through Harvester (OP-7, CHG-1).
//
// Loop 2's passive checks and finding handling (LOOP-8 to LOOP-10) are
// Guard, in secure.go. Loop 3 plugs in as a Source. The package uses no inference (ARC-2).
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package loops
