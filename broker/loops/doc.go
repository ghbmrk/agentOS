// Package loops holds what is left of the autonomous loops (SPEC §11A)
// after the change pipeline's delete (#2785): Loop 2's off-the-shelf
// probe vocabulary and probes (LOOP-7: canary rounds through ../probecmd,
// published corpora, tamper and exhaustion rounds), and the parser for
// the owner's loop settings texts (LOOP-0), which agentosd's learn-state
// sweep reads.
//
// The spare-capacity scheduler, the spare envelope and Loop 2's Guard
// (finding handling, LOOP-8 to LOOP-10) went with the pipeline; the
// HLD-2 to HLD-4 rebuild is a kernel-interface row. Loop 1 and its
// Harvester were deleted earlier (#2786 part a). The package uses no
// inference (ARC-2).
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package loops
