package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
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

// REQ: CH-12. VM-snap-unread-notice-fu-2 (#6292): a held notice over an
// outage of many retry periods, through the real owner link, is one text
// the owner missed: its retries wait for the line rather than be refused
// and counted each time, and it goes once the line is back.
func TestHeldUnreadNoticeOverAnOutageCountsOneMissedText(t *testing.T) {
	const own = "+15550000999"
	link := modemlink.New(modemlink.Config{Owner: own, SendWait: time.Millisecond})
	state := func(line string) {
		t.Helper()
		b, _ := json.Marshal(bridgeproto.State{OwnerLine: line})
		if _, err := link.Ops()[bridgeproto.OpState](context.Background(), sockets.Peer{Kind: "owner"}, b); err != nil {
			t.Fatalf("state %s: %v", line, err)
		}
	}
	state(bridgeproto.StateDown)
	caps := &capState{}
	caps.ownerLineUsable(link.Usable)
	const periods = 20
	var tries, asked atomic.Int32
	sent := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u := newUnreadNotices(ctx, time.Millisecond, func(text string) error {
		tries.Add(1)
		if err := link.Send(own, text); err != nil {
			return err
		}
		sent <- text
		return nil
	})
	enough := make(chan struct{})
	u.up = func() bool {
		if asked.Add(1) == periods {
			close(enough)
		}
		return caps.ownerLineUp()
	}
	u.gone(1, true)
	select {
	case <-enough:
	case <-time.After(5 * time.Second):
		t.Fatalf("the line was asked %d times, want %d", asked.Load(), periods)
	}
	if n := tries.Load(); n != 1 {
		t.Fatalf("%d sends while the line was down, want the first only", n)
	}
	state(bridgeproto.StateOK)
	if o := link.LastOutage(); o.Missed != 1 {
		t.Fatalf("after %d retry periods the outage counts %d missed texts, want 1", periods, o.Missed)
	}
	deadline := time.After(5 * time.Second)
	for tries.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("the held notice was not sent once the line was back")
		case <-time.After(time.Millisecond):
		}
	}
}

// With nothing wired, the owner line reads as up, so a sender tries; once
// wired, it reads as the link says.
func TestOwnerLineUpUntilWired(t *testing.T) {
	caps := &capState{}
	if !caps.ownerLineUp() {
		t.Fatal("an unwired owner line reads as down")
	}
	up := false
	caps.ownerLineUsable(func() bool { return up })
	if caps.ownerLineUp() {
		t.Fatal("a down owner line reads as up")
	}
	up = true
	if !caps.ownerLineUp() {
		t.Fatal("an up owner line reads as down")
	}
}

// openVM gives the held notice the owner line's state, and main wires the
// line's state from the modem bridge's link (#6292).
func TestHeldUnreadNoticeAsksTheOwnerLine(t *testing.T) {
	src, err := os.ReadFile("main.go")
	must(t, err)
	s := string(src)
	link := strings.Index(s, "\t\tlink := modemlink.New(")
	wire := strings.Index(s, "\t\tcaps.ownerLineUsable(link.Usable)\n")
	if link < 0 || wire < link || strings.Count(s, "caps.ownerLineUsable(") != 1 {
		t.Fatal("main.go does not wire the owner line's state from the modem link once, after making it")
	}
	if open := strings.Index(s, "openVM(ctx, vmc, caps,"); open < wire {
		t.Fatalf("openVM at %d, before the owner line is wired at %d", open, wire)
	}
	caps := &capState{}
	caps.ownerLineUsable(func() bool { return false })
	var tries int
	told := make(chan struct{}, 1)
	state := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(state, "snapshots", "s0000000007", "meta.json"), 0o700))
	var m *vm.Manager
	adm, err := admission.New(admission.Config{CapacityMB: 8000}, lateManager{&m})
	must(t, err)
	defer func(d time.Duration) { unreadRetry = d }(unreadRetry)
	unreadRetry = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	m, err = openVM(ctx, vm.Config{
		StateDir: state, Images: map[string]string{"base": t.TempDir()},
		Runtime: &sleepRuntime{running: map[string]bool{}}, Admit: adm, NoCgroups: true, NoQuota: true,
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
	}, caps, func(string) error {
		mu.Lock()
		defer mu.Unlock()
		tries++
		if tries > 1 {
			told <- struct{}{}
		}
		return modem.ErrNotSent
	})
	must(t, err)
	must(t, m.ForgetSince(context.Background(), "x.0", time.Now()))
	select {
	case <-told:
		t.Fatal("a held notice was sent again while the owner line was down")
	case <-time.After(50 * unreadRetry):
	}
	mu.Lock()
	defer mu.Unlock()
	if tries != 1 {
		t.Fatalf("%d sends, want the first only", tries)
	}
}

// REQ: LOG-4. #6292: refusals while a retry is armed arm no second timer,
// so one held notice never runs as parallel retry loops.
func TestRepeatedUnreadRefusalsArmOneTimer(t *testing.T) {
	u := newUnreadNotices(context.Background(), time.Hour, func(string) error { return modem.ErrNotSent })
	u.gone(1, true)
	u.mu.Lock()
	first := u.timer
	u.mu.Unlock()
	if first == nil {
		t.Fatal("a refusal armed no retry")
	}
	defer first.Stop()
	u.gone(1, false)
	u.flush()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.timer != first {
		t.Fatal("a refusal while a retry was armed armed another timer")
	}
}
