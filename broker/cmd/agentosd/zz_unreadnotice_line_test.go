package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
	"github.com/ghbmrk/agentos/broker/vm"
)

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

// openVM gives the held notice the owner line's state: while the wired
// line is down, a refused notice is not sent again (#6292). main's wiring
// of the modem link's state is the follow-up row.
func TestHeldUnreadNoticeAsksTheOwnerLine(t *testing.T) {
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
