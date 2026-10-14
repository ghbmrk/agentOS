//go:build race

package journal

// modelRaceCut is how many levels TestOP2SameEffectModel drops under the
// race detector. The search is sequential, so the detector finds nothing
// in it, and at full depth it takes minutes and gigabytes there; the
// plain run (go test without -race) keeps the full bounds.
const modelRaceCut = 1
