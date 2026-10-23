// Package loops is the spare-capacity scheduler shared by the three
// autonomous loops (SPEC §11A, LOOP-0 to LOOP-3).
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
// Loop model calls (counterfactual replay, the clean-room builder) are
// metered against one dedicated meter, the spare budget, separate from every work budget (LOOP-2, OP-8). Its cap is an
// owner setting, changed only by an owner-origin intent; nothing a loop
// runs can raise it (LOOP-6, CHG-2).
//
// Loop 1, which mined the journal for hypotheses, and its Harvester were
// deleted (#2786 part a, HLD-4: off until it beats the baseline); its
// builder contract went with loopbuild (#2787).
//
// Loop 2's passive checks and finding handling (LOOP-8 to LOOP-10) are
// Guard, in secure.go. Loop 3 plugs in as a Source. The package uses no inference (ARC-2).
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package loops
