package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: LOG-4, CH-12. VM-snap-unread-notice-fu (#5500): a retry streak is
// logged once at its start, its end once, a refusal that may hide a sent
// text once, and a later streak starts its own log line.
func TestUnreadNoticeLogsEachStreakOnce(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	errs := []error{modem.ErrNotSent, modem.ErrNotSent, nil, nil, modem.ErrNotSent, modem.ErrDown}
	tries := 0
	u := newUnreadNotices(context.Background(), time.Hour, func(string) error {
		err := errs[tries]
		tries++
		return err
	})
	defer func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.timer != nil {
			u.timer.Stop()
		}
	}()
	count := func(s string) int { return strings.Count(logged.String(), s) }
	step := func(name string, do func(), streaks, recovered, maybe int) {
		t.Helper()
		do()
		if got := [3]int{count("trying again every"), count("after retrying"), count("it may have gone")}; got != [3]int{streaks, recovered, maybe} {
			t.Fatalf("%s: streak starts, recoveries, maybe-sent logged %v, want %v; log:\n%s", name, got, [3]int{streaks, recovered, maybe}, logged.String())
		}
	}
	step("first refusal", func() { u.gone(1, true) }, 1, 0, 0)
	step("refused again", u.flush, 1, 0, 0)
	step("delivered after retrying", u.flush, 1, 1, 0)
	step("delivered at once", func() { u.gone(1, true) }, 1, 1, 0)
	step("a new streak", func() { u.gone(1, false) }, 2, 1, 0)
	step("may have gone", u.flush, 2, 1, 1)
	if tries != len(errs) {
		t.Fatalf("%d sends, want %d", tries, len(errs))
	}
}

// After a retry delivers, the hold takes new notices again and a new
// refusal arms a new retry, which delivers too.
func TestUnreadNoticeRetriesEachStreak(t *testing.T) {
	var tries atomic.Int32
	told := make(chan string, 4)
	u := newUnreadNotices(context.Background(), time.Millisecond, func(text string) error {
		if tries.Add(1)%2 == 1 {
			return modem.ErrNotSent
		}
		told <- text
		return nil
	})
	for _, forgotten := range []bool{true, false} {
		done := make(chan struct{})
		go func() { u.gone(2, forgotten); close(done) }()
		select {
		case got := <-told:
			if want := unreadGoneNotice(2, forgotten); got != want {
				t.Fatalf("told %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("notice (forgotten %v) never retried after %d tries", forgotten, tries.Load())
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the hold stayed locked after a retry")
		}
	}
	if n := tries.Load(); n != 4 {
		t.Fatalf("%d tries, want 4", n)
	}
}

// informOwner refuses before the owner channel is up with a refusal that
// proves nothing went, so the deletion notice is retried rather than lost.
func TestInformOwnerWithoutChannelIsNotSent(t *testing.T) {
	err := informOwner(func() *owner.Channel { return nil })("x")
	if !errors.Is(err, modem.ErrNotSent) || !unreadNotSent(err) {
		t.Fatalf("no channel: %v, want a not-sent refusal", err)
	}
}
