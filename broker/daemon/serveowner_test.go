package daemon

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-13, OP-4, GR10, ARC-2, CH-2

// With no modem, serveOwner reports what a restart dropped, keeps serving
// (its minute tick expires requests) while its context lives, and returns
// once it ends (CH-13, OP-4).
func TestServeOwnerBootsServesAndStopsWithNoModem(t *testing.T) {
	dir := t.TempDir()
	_, d := start(t, dir)
	var mu sync.Mutex
	var decided []string
	store := &ownerch.MemStore{}
	store.Save(ownerch.State{Pending: []ownerch.PendingRef{{ID: "7", Refs: []string{"old/1"}}}})
	ch, err := ownerch.New(ownerch.Config{
		Owner: owner, Engine: d.Owned(), Store: store,
		Decide: func(dc ownerch.Decision) {
			mu.Lock()
			decided = append(decided, dc.Ref+" "+dc.Why)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() { serveOwner(ctx, ch, false); close(served) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := slices.Clone(decided)
		mu.Unlock()
		if slices.Contains(got, "old/1 restart") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("decided %q: want the restart's drop", got)
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-served:
		t.Fatal("serveOwner returned while its context lives")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("serveOwner did not return once its context ended")
	}
}

// With a modem, the owner channel serves it: the owner's text is answered
// on the line (P1-5).
func TestTheOwnerChannelServesTheModem(t *testing.T) {
	dir := t.TempDir()
	carrier := modem.NewCarrier()
	phone := carrier.Line(owner)
	startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState, c.Modem = nil, filepath.Join(dir, "owner.json"), carrier.Line("+15550000009")
	})
	if err := phone.Send("+15550000009", "HELP"); err != nil {
		t.Fatal(err)
	}
	if got := nextText(t, phone); !strings.Contains(got, "STOP") {
		t.Fatalf("HELP by text: %q", got)
	}
}

// A restart carries an intent left pending under STOP: the owner channel's
// boot hands it to the gate, which holds it while STOP holds, and once
// RESUME lifts it the gate's tick asks about it again (GR10,
// SEC-failed-stop-latch), here refused, as there is no grant (OP-4). The
// tick is the gate's own (grants.DefaultTick), so this test waits for one;
// it runs in parallel with the others.
func TestARestartAsksAboutAPendingIntentAgainAfterRESUME(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	in := journal.Intent{ID: "m1/r1", Origin: "guest:m1", Account: "mail", Action: "message.send", Executor: "grants"}
	cancel, d := startWith(t, dir, func(c *Config) { c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json") })
	if st, err := d.Gate().Submit(in); err != nil || st.State != journal.Pending {
		t.Fatalf("submit: %s %v", st.State, err)
	}
	if _, err := d.Owned().Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancel()
	d.Wait()
	_, d = startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
	})
	time.Sleep(20 * time.Millisecond)
	if st, err := d.Engine().Get(in.ID); err != nil || st.State != journal.Pending {
		t.Fatalf("under STOP the intent is %s %v", st.State, err)
	}
	if err := d.Owned().Resume(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(grants.DefaultTick + 5*time.Second)
	for {
		st, err := d.Engine().Get(in.ID)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == journal.Denied {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after RESUME the intent is %s, not asked about again", st.State)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// With the owner channel on, the owner socket's texts reach it, not the
// bare control words: RETRY is the channel's (OP-2).
func TestTheOwnerSocketsTextsReachTheOwnerChannel(t *testing.T) {
	dir := t.TempDir()
	startWith(t, dir, func(c *Config) { c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json") })
	if r := text(t, dir, owner, "RETRY"); len(r) != 1 || r[0] != "Nothing to retry." {
		t.Fatalf("RETRY on the owner socket: %q", r)
	}
}
