package devhost_test

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: DEV-8, DEV-4

// subDecl is the fixture with a subscription, and a second reading kind.
func subDecl() devslot.Declaration {
	d := fixture.Declaration()
	d.Operations = append(d.Operations, devslot.Operation{Name: "watch", Verb: key.Read, Shapes: []string{"get"}, MaxWrites: 1, Subscribe: true})
	d.Readings = append(d.Readings, "smoke")
	return d
}

// declareSub sends subDecl and takes the op message.
func declareSub(t *testing.T, c net.Conn) bool {
	t.Helper()
	b, _ := devslot.Canonical(subDecl())
	if !send(t, c, devslot.Msg{T: devslot.MsgDeclare, B: b}) {
		return false
	}
	m, err := recv(t, c)
	if err != nil || m.T != devslot.MsgOp {
		t.Errorf("host's reply to the declaration: %+v, %v", m, err)
		return false
	}
	return true
}

// notify is a sink that also signals each event.
type notify struct {
	sink
	ch chan devhost.Event
}

func (n *notify) Emit(e devhost.Event) error {
	n.sink.Emit(e)
	n.ch <- e
	return nil
}

func newNotify() *notify { return &notify{ch: make(chan devhost.Event, 1024)} }

func (n *notify) next(t *testing.T) devhost.Event {
	t.Helper()
	select {
	case e := <-n.ch:
		return e
	case <-time.After(3 * time.Second):
		t.Fatalf("no event")
		return devhost.Event{}
	}
}

// subHost lowers the MinSubscription floor to sub for the test, so a test
// of other behaviour need not wait out real instances;
// TestNewRefusesShortSubscription holds the floor itself.
func subHost(t *testing.T, d *dialer, s devhost.Sink, sub time.Duration, lim devhost.Limit, now func() time.Time) *devhost.Host {
	t.Helper()
	devhost.LowerMinSubscription(t, sub)
	h, err := devhost.New(devhost.Config{
		Decl: subDecl(), Pin: pin, Dialer: d, Transport: &transport{}, Sink: s,
		Deadline: 5 * time.Second, Subscription: sub, Limit: lim, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// subDriver is a real driver behind the real slot: it asks once, then
// reports each frame the device sends until the subscription ends.
type subDriver struct{}

func (subDriver) Declare() devslot.Declaration { return subDecl() }

func (subDriver) Run(ctx context.Context, _ string, l devslot.Link, _ devslot.Secrets) ([]devslot.Reading, error) {
	if err := l.Write(ctx, "control", []byte{fixture.OpGet}); err != nil {
		return nil, nil
	}
	for {
		_, f, err := l.Read(ctx)
		if err != nil {
			return nil, nil
		}
		if len(f) != 1 {
			return nil, errors.New("bad frame")
		}
		if err := l.Report(devslot.Reading{Kind: "temperature", Value: int64(f[0]), Time: time.Unix(0x65000000, 0)}); err != nil {
			return nil, err
		}
	}
}

func TestSubscribeEmitsPerReading(t *testing.T) {
	t.Run("wire", func(t *testing.T) {
		held := make(chan struct{})
		d := &dialer{t: t, scripts: []script{func(t *testing.T, c net.Conn) {
			if !declareSub(t, c) {
				return
			}
			send(t, c, reading("temperature", 0, okTime))
			<-held // the reading is out before anything else is sent
			send(t, c, reading("smoke", 0, okTime))
			send(t, c, devslot.Msg{T: devslot.MsgDone})
		}}}
		defer d.done.Wait()
		var once sync.Once
		release := func() { once.Do(func() { close(held) }) }
		defer release()
		s := newNotify()
		h := subHost(t, d, s, 5*time.Second, devhost.Limit{Burst: 10, Window: time.Minute}, nil)
		type res struct {
			n   int
			err error
		}
		out := make(chan res, 1)
		go func() { n, err := h.Subscribe(context.Background(), "watch"); out <- res{n, err} }()
		if e := s.next(t); e.Reading.Kind != "temperature" || e.Op != "watch" || !e.Unverified || e.Label != devslot.Label {
			t.Fatalf("first event %+v", e)
		}
		release()
		if e := s.next(t); e.Reading.Kind != "smoke" {
			t.Fatalf("second event %+v", e)
		}
		if r := <-out; r.n != 2 || r.err != nil {
			t.Fatalf("Subscribe: %d, %v; want 2 readings and a clean end", r.n, r.err)
		}
	})
	t.Run("slot", func(t *testing.T) {
		tr := &transport{}
		d := &dialer{t: t, scripts: []script{func(t *testing.T, c net.Conn) {
			devslot.ServeWire(context.Background(), subDriver{}, c)
		}}}
		defer d.done.Wait()
		s := newNotify()
		h, err := devhost.New(devhost.Config{
			Decl: subDecl(), Pin: pin, Dialer: d, Transport: tr, Sink: s,
			Deadline: time.Second, Subscription: devhost.MinSubscription, Limit: devhost.Limit{Burst: 10, Window: time.Minute},
		})
		if err != nil {
			t.Fatal(err)
		}
		tr.queue("data", []byte{7})
		tr.queue("data", []byte{8})
		ctx, cancel := context.WithCancel(context.Background())
		out := make(chan error, 1)
		go func() { _, err := h.Subscribe(ctx, "watch"); out <- err }()
		for _, v := range []int64{7, 8} {
			if e := s.next(t); e.Reading.Value != v || e.Reading.Time.Location() != time.UTC {
				t.Fatalf("event %+v, want value %d in UTC", e, v)
			}
		}
		cancel()
		if err := <-out; !errors.Is(err, context.Canceled) {
			t.Fatalf("Subscribe after cancel: %v", err)
		}
		if tr.writes == nil || len(tr.writes) != 1 {
			t.Fatalf("writes %v, want the one get frame", tr.writes)
		}
	})
}

func TestSubscribeFloodCoalesced(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)}
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clk.t }
	d := &dialer{t: t, scripts: []script{func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		for i := range 50 {
			send(t, c, reading("temperature", 0, okTime))
			if i == 25 {
				send(t, c, reading("smoke", 0, okTime))
			}
		}
		send(t, c, devslot.Msg{T: devslot.MsgDone})
	}}}
	defer d.done.Wait()
	s := &sink{}
	h := subHost(t, d, s, 5*time.Second, devhost.Limit{Burst: 2, Window: time.Minute}, now)
	if n, err := h.Subscribe(context.Background(), "watch"); n != 51 || err != nil {
		t.Fatalf("Subscribe: %d, %v", n, err)
	}
	kinds := func() (out []string) {
		for _, e := range s.events {
			out = append(out, e.Reading.Kind)
		}
		return out
	}
	// The smoke reading has its own window, so the temperature flood does
	// not hide it, and it goes out as it arrives.
	if len(s.events) != 3 || s.events[2].Reading.Kind != "smoke" || s.events[2].Coalesced != 0 {
		t.Fatalf("events inside the window: %v, want temperature twice and the smoke reading", kinds())
	}
	h.Flush()
	if len(s.events) != 3 {
		t.Fatalf("the coalesced event went out before its window ended")
	}
	mu.Lock()
	clk.t = clk.t.Add(time.Minute)
	mu.Unlock()
	h.Flush()
	if len(s.events) != 4 || s.events[3].Coalesced != 48 || s.events[3].Reading.Kind != "temperature" {
		t.Fatalf("events %+v, want one coalesced temperature event counting 48", s.events[3:])
	}
}

func TestSubscribeEndsAtDeadlineAndResumes(t *testing.T) {
	const sub = 200 * time.Millisecond
	var mu sync.Mutex
	var ended []time.Time
	stays := func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		send(t, c, reading("temperature", 0, okTime))
		if !closed(c) {
			t.Errorf("host kept a subscription's instance past its deadline")
		}
		mu.Lock()
		ended = append(ended, time.Now())
		mu.Unlock()
	}
	ends := func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		send(t, c, reading("temperature", 0, okTime))
		send(t, c, devslot.Msg{T: devslot.MsgDone})
	}
	d := &dialer{t: t, scripts: []script{stays, stays, ends}}
	s := &sink{}
	h := subHost(t, d, s, sub, devhost.Limit{Burst: 10, Window: time.Minute}, nil)
	n, err := h.Subscribe(context.Background(), "watch")
	d.done.Wait()
	if n != 3 || err != nil {
		t.Fatalf("Subscribe: %d, %v; want a reading from each of three instances", n, err)
	}
	if d.dials != 3 || len(ended) != 2 {
		t.Fatalf("%d instances, %d ended at the deadline; want 3 and 2", d.dials, len(ended))
	}
	// The host starts each instance's deadline just before it dials, so
	// the deadline its dial carried is at most sub after the dial, and
	// short of it only by the few statements between the two (slack).
	// The instance must not end before that deadline.
	const slack = 10 * time.Millisecond
	for i, end := range ended {
		dl, at := d.deadlines[i], d.at[i]
		if span := dl.Sub(at); dl.IsZero() || span > sub || span < sub-slack {
			t.Fatalf("instance %d was dialed with a deadline %v after the dial, want %v", i, span, sub)
		}
		if end.Before(dl) || end.Sub(dl) > 2*time.Second {
			t.Fatalf("instance %d ended %v after its deadline, want at or soon after it", i, end.Sub(dl))
		}
	}

	// An instance that ends any other way ends the subscription.
	bad := func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		send(t, c, reading("temperature", 0, okTime))
		send(t, c, reading("humidity", 0, okTime))
		closed(c)
	}
	d = &dialer{t: t, scripts: []script{bad, ends}}
	s = &sink{}
	h = subHost(t, d, s, 5*time.Second, devhost.Limit{Burst: 10, Window: time.Minute}, nil)
	n, err = h.Subscribe(context.Background(), "watch")
	d.done.Wait()
	if !errors.Is(err, devslot.ErrReading) || n != 1 || d.dials != 1 {
		t.Fatalf("Subscribe after an undeclared kind: %d, %v, %d dials; want the refusal, the earlier reading only, no resume", n, err, d.dials)
	}
}

func TestDoPreemptsSubscription(t *testing.T) {
	stays := func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		send(t, c, reading("temperature", 0, okTime))
		closed(c)
	}
	ends := func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		send(t, c, devslot.Msg{T: devslot.MsgDone})
	}
	one := func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		send(t, c, reading("temperature", 0, okTime))
		send(t, c, devslot.Msg{T: devslot.MsgDone})
	}
	d := &dialer{t: t, scripts: []script{stays, one, ends}}
	defer d.done.Wait()
	s := newNotify()
	h := subHost(t, d, s, time.Minute, devhost.Limit{Burst: 10, Window: time.Minute}, nil)
	out := make(chan error, 1)
	go func() { _, err := h.Subscribe(context.Background(), "watch"); out <- err }()
	s.next(t)
	start := time.Now()
	if n, err := h.Do(context.Background(), "read-temperature"); n != 1 || err != nil {
		t.Fatalf("Do during a subscription: %d, %v", n, err)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("Do waited %v for the subscription", el)
	}
	if err := <-out; err != nil {
		t.Fatalf("Subscribe after Do: %v, want it resumed and ended cleanly", err)
	}
	if d.dials != 3 {
		t.Fatalf("%d dials, want the subscription, Do, and the resumed subscription", d.dials)
	}
}

func TestSubscriptionIsItsOwnCall(t *testing.T) {
	d := &dialer{t: t}
	h := subHost(t, d, &sink{}, time.Second, devhost.Limit{Burst: 1, Window: time.Second}, nil)
	if _, err := h.Do(context.Background(), "watch"); !errors.Is(err, devhost.ErrSubscription) {
		t.Fatalf("Do on a subscription: %v", err)
	}
	if _, err := h.Subscribe(context.Background(), "read-temperature"); !errors.Is(err, devhost.ErrSubscription) {
		t.Fatalf("Subscribe on a one-shot operation: %v", err)
	}
	if d.dials != 0 {
		t.Fatalf("a refused call dialed the driver")
	}
	_, err := devhost.New(devhost.Config{
		Decl: subDecl(), Pin: pin, Dialer: d, Transport: &transport{}, Sink: &sink{},
		Deadline: time.Second, Limit: devhost.Limit{Burst: 1, Window: time.Second},
	})
	if err == nil {
		t.Fatalf("a declaration with a subscription was accepted with no subscription deadline")
	}
}

// TestSubscriptionYieldsToWaitingDo: a subscription that is already waiting
// for the driver when a Do arrives lets that Do run first, rather than
// starting an instance the Do would then wait out (L3 6455017977 point 1 on
// #3509).
func TestSubscriptionYieldsToWaitingDo(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{})
	gated := func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		close(started)
		<-gate
		send(t, c, devslot.Msg{T: devslot.MsgDone})
	}
	one := func(t *testing.T, c net.Conn) {
		if !declareSub(t, c) {
			return
		}
		send(t, c, reading("temperature", 0, okTime))
		send(t, c, devslot.Msg{T: devslot.MsgDone})
	}
	// The subscription's instance holds the connection open until the
	// host closes it at the cancel, so the cancel is the only way it ends.
	// It may be cancelled before the host answers its declaration, so it
	// checks nothing.
	stays := func(t *testing.T, c net.Conn) {
		b, _ := devslot.Canonical(subDecl())
		send(t, c, devslot.Msg{T: devslot.MsgDeclare, B: b})
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			if _, err := devslot.ReadMsg(c); err != nil {
				return
			}
		}
	}
	d := &dialer{t: t, scripts: []script{gated, one, stays}}
	defer d.done.Wait()
	h := subHost(t, d, &sink{}, time.Minute, devhost.Limit{Burst: 10, Window: time.Minute}, nil)
	first := make(chan error, 1)
	go func() { _, err := h.Do(context.Background(), "read-temperature"); first <- err }()
	<-started
	// The subscription passes its wait (no Do is pending) and queues for
	// the driver behind the first Do.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub := make(chan error, 1)
	go func() { _, err := h.Subscribe(ctx, "watch"); sub <- err }()
	parked(t, "(*Host).acquire")
	// A second Do arrives while no instance runs, so there is nothing for
	// it to preempt; it queues behind the subscription.
	type res struct {
		n   int
		err error
	}
	second := make(chan res, 1)
	go func() { n, err := h.Do(context.Background(), "read-temperature"); second <- res{n, err} }()
	parked(t, "(*Host).Do")
	close(gate)
	if err := <-first; err != nil {
		t.Fatalf("first Do: %v", err)
	}
	select {
	case r := <-second:
		if r.n != 1 || r.err != nil {
			t.Fatalf("second Do: %d, %v; want it to run before the subscription's instance", r.n, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("second Do waited for a subscription instance that started after it")
	}
	cancel()
	if err := <-sub; !errors.Is(err, context.Canceled) {
		t.Fatalf("Subscribe: %v", err)
	}
}

// parked waits until a goroutine whose stack holds fn is parked on a mutex:
// in this test, only h.mu is held long enough for a caller to park on it.
func parked(t *testing.T, fn string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if strings.Contains(g, "[sync.Mutex.Lock") && strings.Contains(g, fn) {
				return
			}
		}
	}
	t.Fatalf("no goroutine in %s parked on the host's mutex", fn)
}

// New refuses a subscription period below MinSubscription, so the host's
// config alone cannot raise a subscription's write rate: each instance
// writes up to MaxWrites, and instances start at most once per period plus
// once after each Do (#4515).
func TestNewRefusesShortSubscription(t *testing.T) {
	cfg := func(sub time.Duration) devhost.Config {
		return devhost.Config{
			Decl: subDecl(), Pin: pin, Dialer: &dialer{t: t}, Transport: &transport{}, Sink: &sink{},
			Deadline: time.Second, Subscription: sub, Limit: devhost.Limit{Burst: 1, Window: time.Second},
		}
	}
	for _, sub := range []time.Duration{0, time.Millisecond, devhost.MinSubscription - time.Nanosecond} {
		if _, err := devhost.New(cfg(sub)); err == nil {
			t.Fatalf("New took a subscription period of %v, below %v", sub, devhost.MinSubscription)
		}
	}
	if _, err := devhost.New(cfg(devhost.MinSubscription)); err != nil {
		t.Fatalf("New refused MinSubscription: %v", err)
	}
	// A declaration with no subscription needs no period.
	c := cfg(0)
	c.Decl = fixture.Declaration()
	if _, err := devhost.New(c); err != nil {
		t.Fatalf("New refused a declaration without a subscription: %v", err)
	}
}
