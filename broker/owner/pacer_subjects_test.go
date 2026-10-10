package owner

import (
	"testing"
	"time"
)

// REQ: CH-15, OWN-4 (PACE-1 PC-1, PC-2)
func TestHeldTextIsRevalidatedAtRelease(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	open := map[string]bool{}
	current := func(subjects []string) bool {
		for _, s := range subjects {
			if open[s] {
				return false
			}
		}
		return true
	}
	r.ch.SetCurrent(current)
	if err := r.ch.PostAbout(ClassUpdate, "Cleared: A.", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.PostAbout(ClassUpdate, "Cleared: B.", []string{"b"}); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.Inform("Plain update."); err != nil {
		t.Fatal(err)
	}
	// The held texts and their subjects survive a restart (PC-1).
	r.ch = r.open()
	r.ch.SetCurrent(current)
	if h := r.held(); len(h) != 3 || len(h[0].Subjects) != 1 || h[0].Subjects[0] != "a" {
		t.Fatalf("hold after restart: %+v", h)
	}
	// A comes back before quiet hours end: its held clear is stale (PC-2).
	open["a"] = true
	r.advance(8*time.Hour + time.Minute) // 07:01
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 1 || got[0] != "Cleared: B. / Plain update." {
		t.Fatalf("released: %q", got)
	}
	if h := r.held(); len(h) != 0 {
		t.Fatalf("stale text still held: %+v", h)
	}
	// The dropped text was never sent, so it spent no allowance.
	if n := r.ch.Allowance(r.clock()); n != DefaultTextsPerHour-1 {
		t.Fatalf("allowance %d", n)
	}
}

// REQ: CH-15, OWN-4 (PACE-1 PC-3)
func TestTextWithSubjectsFailsClosed(t *testing.T) {
	// No hook attached: a text whose subjects nothing can confirm is
	// dropped, at release and when it would go now.
	r := pacedRig(t, quiet22to7(), 23, 0)
	if err := r.ch.PostAbout(ClassUpdate, "Cleared: A.", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	r.advance(8*time.Hour + time.Minute)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.PostAbout(ClassUpdate, "Cleared: B.", []string{"b"}); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("sent with no hook: %q", got)
	}
	// With the hook, one that would go now is checked too.
	r.ch.SetCurrent(func(s []string) bool { return s[0] != "c" })
	r.ch.PostAbout(ClassUpdate, "Cleared: C.", []string{"c"})
	r.ch.PostAbout(ClassUpdate, "Cleared: D.", []string{"d"})
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Cleared: D." {
		t.Fatalf("sent: %q", got)
	}
}
