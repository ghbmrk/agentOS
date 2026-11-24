package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: LOG-4, CH-12. VM-snap-unread-notice-fu (#5500): a deletion notice the
// owner channel did not take is held and retried until it goes, and goes
// once: an Inform that fails once, then succeeds, tells the owner once.
func TestOpenVMRetriesUnreadNoticeUntilDelivered(t *testing.T) {
	defer func(d time.Duration) { unreadRetry = d }(unreadRetry)
	unreadRetry = 10 * time.Millisecond
	state := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(state, "snapshots", "s0000000007", "meta.json"), 0o700))
	var m *vm.Manager
	adm, err := admission.New(admission.Config{CapacityMB: 8000}, lateManager{&m})
	must(t, err)
	var tries atomic.Int32
	told := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, err = openVM(ctx, vm.Config{
		StateDir: state, Images: map[string]string{"base": t.TempDir()},
		Runtime: &sleepRuntime{running: map[string]bool{}}, Admit: adm, NoCgroups: true, NoQuota: true,
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
	}, &capState{}, func(text string) error {
		if tries.Add(1) == 1 {
			return errNoOwnerChannel
		}
		told <- text
		return nil
	})
	must(t, err)
	must(t, m.ForgetSince(context.Background(), "x.0", time.Now()))
	select {
	case got := <-told:
		if got != unreadGoneNotice(1, true) {
			t.Fatalf("owner told %q, want the forget notice", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the held notice was never retried")
	}
	time.Sleep(10 * unreadRetry)
	if n := tries.Load(); n != 2 || len(told) != 0 {
		t.Fatalf("%d tries, %d more told: want one failure, then one delivery", n, len(told))
	}
}

// Notices held while the channel is down are summed by kind, so a long
// outage owes at most one forget and one disk-space notice, each with the
// true count; a cancelled context stops the retries.
func TestUnreadNoticesSumWhileHeldAndStopWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	down := true
	var told []string
	u := newUnreadNotices(ctx, time.Hour, func(text string) error {
		if down {
			return modem.ErrNotSent
		}
		told = append(told, text)
		return nil
	})
	u.gone(1, true)
	u.gone(2, false)
	u.gone(2, true)
	if len(told) != 0 {
		t.Fatalf("told while down: %q", told)
	}
	down = false
	u.flush()
	want := []string{unreadGoneNotice(3, true), unreadGoneNotice(2, false)}
	if !slices.Equal(told, want) {
		t.Fatalf("told %q, want %q", told, want)
	}
	u.flush()
	if len(told) != 2 {
		t.Fatalf("a delivered notice was sent again: %q", told)
	}
	down = true
	cancel()
	u.gone(1, false)
	down = false
	u.flush()
	if len(told) != 2 {
		t.Fatalf("retried after the context ended: %q", told)
	}
}

// A send error that does not prove the text stayed (modem.ErrDown: a
// silent bridge, an unknown receipt) may hide a text that reached the
// owner, so the notice counts as told and is never sent twice (#1638,
// #2363; L3 on #6139). Only proven refusals are retried.
func TestUnreadNoticeMaybeSentIsNotSentTwice(t *testing.T) {
	for _, c := range []struct {
		err   error
		tries int
	}{
		{modem.ErrDown, 1},
		{errors.New("owner: save failed"), 1},
		{modem.ErrNotSent, 2},
		{errNoOwnerChannel, 2},
		{owner.ErrNoModem, 2},
	} {
		tries := 0
		u := newUnreadNotices(context.Background(), time.Hour, func(string) error {
			tries++
			if tries == 1 {
				return c.err
			}
			return nil
		})
		u.gone(2, true)
		u.flush()
		u.flush()
		if tries != c.tries {
			t.Errorf("first error %v: %d sends, want %d", c.err, tries, c.tries)
		}
	}
}

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
func TestInformOwnerNotSentOnlyWithoutChannel(t *testing.T) {
	err := informOwner(func() *owner.Channel { return nil })("x")
	if !errors.Is(err, modem.ErrNotSent) || !unreadNotSent(err) {
		t.Fatalf("no channel: %v, want a not-sent refusal", err)
	}
	// Once the channel is up it decides: a channel with no modem refuses
	// with its own plain error, which does not prove the text stayed, so
	// the notice counts as possibly sent.
	err = informOwner(func() *owner.Channel { return &owner.Channel{} })("x")
	if err == nil || errors.Is(err, errNoOwnerChannel) || unreadNotSent(err) {
		t.Fatalf("channel up: %v, want the channel's own refusal", err)
	}
}
