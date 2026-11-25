package kernel_test

// REQ: LOG-4

import (
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Named and OpenContent's Missing list subjects in sorted order, never the
// subject map's order. With twelve subjects a random order is sorted by
// chance once in 12! runs, so the check cannot pass on a lucky map walk.
// Mutant: liveSubjects' slices.Sort deleted (erase.go).
func TestLiveSubjectsAreSorted(t *testing.T) {
	r := newErig(t)
	var subs []string
	for range 12 {
		s := r.open()
		r.seal(s, "mail", kernel.ClassLabel, "Alice")
		subs = append(subs, s)
	}
	slices.Sort(subs)
	got, unread, err := r.k.Named("Alice")
	if err != nil || unread != nil || !slices.Equal(got, subs) {
		t.Fatalf("named %v %v %v, want %v", got, unread, err, subs)
	}
	for _, s := range subs {
		r.keys.MemKeys.Delete(s)
	}
	if rep := r.boot(); !slices.Equal(rep.Missing, subs) {
		t.Fatalf("missing %v, want %v", rep.Missing, subs)
	}
}
