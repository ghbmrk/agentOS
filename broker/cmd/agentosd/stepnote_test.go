package main

// REQ: REV-1

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/vm"
)

// The guest plane learns a failed step snapshot's reason only through
// the plane's own marks; a layer too deep to measure, which the manager
// also reports as a disk budget, is too deep (SR2-3s).
func TestSR23sStepErrMarksTheReason(t *testing.T) {
	deep := fmt.Errorf("%w (%w)", vm.ErrQuota, vm.ErrTooDeep)
	for _, tc := range []struct {
		err      error
		deep, no bool
	}{
		{deep, true, false},
		{fmt.Errorf("%w (layer 9 bytes, cap 1)", vm.ErrQuota), false, true},
		{errors.New("pause failed"), false, false},
	} {
		got := stepErr(tc.err)
		if errors.Is(got, guest.ErrStepTooDeep) != tc.deep || errors.Is(got, guest.ErrStepNoRoom) != tc.no || !errors.Is(got, tc.err) {
			t.Errorf("stepErr(%v) = %v", tc.err, got)
		}
	}
	if stepErr(nil) != nil {
		t.Error("a snapshot taken reports an error")
	}
	var n stepNotes
	if n.Note() != "" {
		t.Error("a line before the plane opens")
	}
}

// The digest carries the Undo line verbatim once it outlasts a digest
// period: daily for 7 days, then weekly, and at once when the line
// changes (UX on SR2-3s R1).
func TestSR23sDigestCadence(t *testing.T) {
	shown := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	line := "Undo: the agent's actions since 08:59 can't be undone yet; its files are full. It has been told to free space. Nothing to do unless this lasts."
	if _, ok := stepDigestKey("", shown, shown.Add(48*time.Hour)); ok {
		t.Fatal("a key with no line")
	}
	if _, ok := stepDigestKey(line, shown, shown.Add(23*time.Hour)); ok {
		t.Fatal("a key inside the first digest period")
	}
	keys := map[string]bool{}
	for h := 24; h <= 24*29; h++ {
		k, ok := stepDigestKey(line, shown, shown.Add(time.Duration(h)*time.Hour))
		if !ok || !strings.HasSuffix(k, line) {
			t.Fatalf("hour %d: key %q", h, k)
		}
		keys[k] = true
	}
	// Days 1 to 7 daily, then weeks from day 8: 8-14, 15-21, 22-28, 29.
	if len(keys) != 7+4 {
		t.Fatalf("%d digest lines in 29 days, want 11", len(keys))
	}
	k1, _ := stepDigestKey(line, shown, shown.Add(30*time.Hour))
	k2, _ := stepDigestKey(strings.Replace(line, "08:59", "10:12", 1), shown, shown.Add(30*time.Hour))
	if k1 == k2 {
		t.Fatal("a new since-time kept the old key")
	}
}
