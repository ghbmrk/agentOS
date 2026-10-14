//go:build race

package journal

// modelRace: TestOP2SameEffectModel is skipped under the race detector.
// The search is sequential, so the detector finds nothing in it, and at
// its bounds it takes minutes and gigabytes there; CI runs it without
// -race at full depth in its own step (Potency P11, L3 L12 on #1433).
const modelRace = true
