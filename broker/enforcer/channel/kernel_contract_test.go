package channel

// REQ: NET-2, A18

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/kernel/chancheck"
)

// The kernel's check (broker/kernel/chancheck) against this channel, on
// one simulated timeline (KRN-6, A18: "a channel message outside the
// format or past the rate is never sent by the kernel, and one a fake core
// sends trips"). The kernel sends every message the gate passes, as fast
// as it passes them; the network delays each one and its answer by a
// seeded amount, in order on a connection; connections drop and the
// kernel restarts; a dropped connection's frames still reach the enforcer
// long after, and its unanswered hello within chancheck.MaxLate; the
// kernel's clock runs fast or slow by up to half a percent. The enforcer
// never trips.

// simConn is one connection of the simulation: the core's end, the frames
// on their way to the enforcer and the answers on their way back.
type simConn struct {
	cl      *client
	ended   bool // the enforcer ended it
	orphan  bool // the kernel gave up on it
	queue   []simFrame
	replies []simFrame
	last    time.Duration // the latest arrival queued: a connection is in order
}

type simFrame struct {
	b  []byte
	tk chancheck.Ticket
	at time.Duration // arrival at the enforcer, or the answer's at the kernel
}

type simKernel struct {
	t      *testing.T
	r      *rig
	rng    *rand.Rand
	base   time.Time
	drift  float64 // the kernel's clock rate, minus one
	gate   *chancheck.Gate
	cur    *simConn
	conns  []*simConn
	id     uint64
	sent   map[wire.RateKind]int
	bypass bool // a fake core: sends what the gate refuses for its rate
}

func (k *simKernel) kclock(t time.Duration) time.Time {
	return k.base.Add(t + time.Duration(float64(t)*k.drift))
}

func (k *simKernel) delay(stall bool) time.Duration {
	if stall {
		return time.Duration(k.rng.Int64N(int64(30 * time.Second)))
	}
	return time.Duration(k.rng.Int64N(int64(20 * time.Millisecond)))
}

func (k *simKernel) msg(kind wire.RateKind) wire.Msg {
	k.id++
	switch kind {
	case wire.RateCommand:
		return cmd(k.id, "lamp", wire.VerbOn)
	case wire.RateTighten:
		return wire.Tighten{ID: k.id, Kind: wire.CutVendorCloud, Device: "tv"}
	case wire.RateRead:
		return wire.Read{ID: k.id, What: wire.ReadCounts}
	case wire.RateAnnounce:
		return wire.Announce{ID: k.id}
	case wire.RateHead:
		if k.id%2 == 0 {
			return wire.Entry{ID: k.id, Body: []byte{1}}
		}
		return wire.Head{ID: k.id}
	case wire.RateAnswer:
		return wire.Challenge{Answer: true, ID: k.id, Data: []byte{7}}
	}
	h, err := wire.SignHello(wire.RoleCore, k.r.core, exporter)
	if err != nil {
		k.t.Fatal(err)
	}
	return h
}

// try sends one message of kind if the gate passes it.
func (k *simKernel) try(kind wire.RateKind, now time.Duration, stall bool) {
	m := k.msg(kind)
	b, tk, err := k.gate.Frame(m, k.kclock(now))
	if errors.Is(err, chancheck.ErrRate) && k.bypass && k.cur != nil && !k.cur.orphan {
		f, _ := wire.Encode(wire.ToEnforcer, m)
		b = frameBytes(f.Type, f.Payload)
		err = nil
	}
	if err != nil {
		return
	}
	if kind == wire.RateHello {
		k.cur = &simConn{cl: k.r.connect()}
		k.conns = append(k.conns, k.cur)
	}
	c := k.cur
	at := max(c.last, now) + k.delay(stall)
	c.last = at
	c.queue = append(c.queue, simFrame{b: b, tk: tk, at: at})
	k.sent[kind]++
}

// deliver runs every arrival and answer due by now, in time order.
func (k *simKernel) deliver(now time.Duration, stall bool) {
	for {
		var next *simConn
		var reply bool
		best := now + 1
		for _, c := range k.conns {
			if len(c.queue) > 0 && c.queue[0].at < best {
				next, reply, best = c, false, c.queue[0].at
			}
			if len(c.replies) > 0 && c.replies[0].at < best {
				next, reply, best = c, true, c.replies[0].at
			}
		}
		if next == nil {
			return
		}
		if reply {
			f := next.replies[0]
			next.replies = next.replies[1:]
			if !next.orphan && f.tk != (chancheck.Ticket{}) {
				if err := k.gate.Answered(f.tk, k.kclock(f.at)); err != nil {
					k.t.Fatalf("answer: %v", err)
				}
			}
			continue
		}
		f := next.queue[0]
		next.queue = next.queue[1:]
		if next.ended {
			continue
		}
		k.r.mu.Lock()
		k.r.now = k.base.Add(f.at)
		k.r.mu.Unlock()
		next.cl.conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, werr := next.cl.conn.Write(f.b)
		var rf wire.Frame
		var rerr error
		if werr == nil {
			rf, rerr = wire.ReadFrame(next.cl.conn, wire.ToCore)
		}
		if werr != nil || rerr != nil {
			k.end(next, f.at)
			continue
		}
		if _, err := wire.Decode(wire.ToCore, rf); err != nil {
			k.t.Fatalf("enforcer's answer: %v", err)
		}
		next.replies = append(next.replies, simFrame{tk: f.tk, at: f.at + k.delay(stall)})
	}
}

// end is the enforcer ending c; the kernel sees it at at.
func (k *simKernel) end(c *simConn, at time.Duration) {
	c.ended = true
	c.cl.conn.Close()
	if !c.orphan {
		k.lose(at)
	}
}

// lose is the kernel giving up on its connection at now. The frames still
// queued on it keep travelling: a hello arrives within MaxLate, a request
// at any time after.
func (k *simKernel) lose(now time.Duration) {
	c := k.cur
	if c == nil {
		return
	}
	k.gate.Lost(k.kclock(now))
	k.orphan(c, now)
}

func (k *simKernel) orphan(c *simConn, now time.Duration) {
	c.orphan = true
	k.cur = nil
	for i := range c.queue {
		f := &c.queue[i]
		if f.at < now {
			continue
		}
		if bytes.HasPrefix(f.b, []byte{byte(wire.THello)}) {
			f.at = now + time.Duration(k.rng.Int64N(int64(chancheck.MaxLate*9/10)))
		} else {
			f.at += time.Duration(k.rng.Int64N(int64(10 * time.Minute)))
		}
	}
	for i := 1; i < len(c.queue); i++ { // still in order on the connection
		c.queue[i].at = max(c.queue[i].at, c.queue[i-1].at)
	}
}

// simulate runs one seed for span of simulated time and returns the
// kernel's sends per kind.
func simulate(t *testing.T, seed uint64, span time.Duration, bypass bool) (*rig, map[wire.RateKind]int) {
	r := newRig(t, nil)
	rng := rand.New(rand.NewPCG(seed, 0x4373))
	k := &simKernel{t: t, r: r, rng: rng, base: r.now, drift: (rng.Float64() - 0.5) / 100, sent: map[wire.RateKind]int{}, bypass: bypass}
	k.gate = chancheck.New(k.kclock(0))
	var now time.Duration
	for now < span {
		stall := rng.IntN(200) == 0
		switch x := rng.IntN(20000); {
		case x == 0: // the kernel restarts
			if k.cur != nil {
				k.orphan(k.cur, now)
			}
			k.gate = chancheck.New(k.kclock(now))
		case x < 10:
			k.lose(now)
		}
		if k.cur == nil {
			k.try(wire.RateHello, now, stall)
		}
		for range 4 {
			k.try(wire.RateKinds[1+rng.IntN(len(wire.RateKinds)-1)], now, stall)
		}
		k.deliver(now, stall)
		if r.cut.trips() > 0 {
			return r, k.sent
		}
		now += time.Duration(rng.Int64N(int64(150 * time.Millisecond)))
	}
	for _, c := range k.conns {
		c.cl.conn.Close()
	}
	return r, k.sent
}

// TestHonestKernelNeverTrips (D-255): every message the gate passes, sent
// as soon as it passes, under delays, stalls, dropped connections whose
// frames arrive late, restarts and clock drift, never trips the real
// channel. The kernel still reaches every kind's rate, so the check is not
// passing by sending nothing.
func TestHonestKernelNeverTrips(t *testing.T) {
	span := 2 * time.Hour
	seeds := uint64(4)
	if testing.Short() {
		span, seeds = 30*time.Minute, 2
	}
	for seed := range seeds {
		r, sent := simulate(t, seed, span, false)
		if n := r.cut.trips(); n != 0 {
			t.Fatalf("seed %d: the honest kernel tripped the enforcer %d times: %v", seed, n, r.cut.reasons)
		}
		for _, kind := range wire.RateKinds[1:] {
			l := wire.Rate(kind)
			// A share of the rate's sustained pace: each attempt waits a
			// round trip and a step, and connections keep dropping.
			if want := int(span/l.Every) / 32; sent[kind] < want {
				t.Errorf("seed %d: kind %d sent %d, want at least %d", seed, kind, sent[kind], want)
			}
		}
	}
}

// TestFakeCoreTrips (A18): the same simulation with a fake core that sends
// what the gate refuses for its rate trips the enforcer; and a message the
// gate refuses as outside the format, sent anyway, trips it too.
func TestFakeCoreTrips(t *testing.T) {
	if r, _ := simulate(t, 1, time.Hour, true); r.cut.trips() == 0 {
		t.Fatal("a fake core past the rate never tripped")
	}
	r := newRig(t, nil)
	g := chancheck.New(start)
	bad := wire.Command{ID: 1, Device: "no such name!", Verb: wire.VerbOn}
	if _, _, err := g.Frame(bad, start); !errors.Is(err, chancheck.ErrFormat) {
		t.Fatalf("the gate passed a message outside the format: %v", err)
	}
	cl := r.dial()
	p := []byte{0, 0, 0, 0, 0, 0, 0, 1, byte(wire.VerbOn), 0}
	p = append(p, byte(len(bad.Device)))
	p = append(p, bad.Device...)
	cl.conn.SetDeadline(time.Now().Add(5 * time.Second))
	go cl.conn.Write(frameBytes(wire.TCommand, p))
	var b [1]byte
	if _, err := cl.conn.Read(b[:]); err == nil || !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("the enforcer answered a malformed command: %v", err)
	}
	<-cl.done
	if r.cut.trips() != 1 {
		t.Fatalf("a malformed command from a fake core: %d trips, want 1", r.cut.trips())
	}
}

// kernelLine drives the gate by hand against the rig, on the enforcer's
// clock: the kernel's clock is the same here, and Margin only slows it.
type kernelLine struct {
	t *testing.T
	r *rig
	g *chancheck.Gate
}

func (k *kernelLine) at() time.Time { k.r.mu.Lock(); defer k.r.mu.Unlock(); return k.r.now }

// frame is the gate's bytes for m now; it fails the test on a refusal.
func (k *kernelLine) frame(m wire.Msg) ([]byte, chancheck.Ticket) {
	k.t.Helper()
	b, tk, err := k.g.Frame(m, k.at())
	if err != nil {
		k.t.Fatalf("the gate refused %T: %v", m, err)
	}
	return b, tk
}

// exchange writes b on cl and reads the enforcer's answer, or reports
// that the enforcer ended the connection.
func exchange(cl *client, b []byte) bool {
	cl.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cl.conn.Write(b); err != nil {
		return false
	}
	_, err := wire.ReadFrame(cl.conn, wire.ToCore)
	return err == nil
}

// hello opens a connection through the gate, if it passes one now.
func (k *kernelLine) hello() (*client, bool) {
	k.t.Helper()
	h, _ := wire.SignHello(wire.RoleCore, k.r.core, exporter)
	b, tk, err := k.g.Frame(h, k.at())
	if errors.Is(err, chancheck.ErrRate) {
		return nil, false
	}
	if err != nil {
		k.t.Fatal(err)
	}
	cl := k.r.connect()
	if !exchange(cl, b) {
		k.t.Fatal("the enforcer refused the hello")
	}
	if err := k.g.Answered(tk, k.at()); err != nil {
		k.t.Fatal(err)
	}
	return cl, true
}

// helloBurst opens connections as fast as the gate passes them for d,
// in steps of one second, closing each.
func (k *kernelLine) helloBurst(d time.Duration) int {
	n := 0
	for end := k.at().Add(d); k.at().Before(end); k.r.advance(time.Second) {
		for {
			cl, ok := k.hello()
			if !ok {
				break
			}
			n++
			k.g.Lost(k.at())
			cl.conn.Close()
		}
	}
	return n
}

// TestLateFrameOfReplacedConnection (ENF-d-9, KRN-chan-2): a command on a
// connection the kernel gave up on reaches the enforcer only after a new
// connection's hello was answered and the command rate refilled. It is
// not counted, so the full burst the gate then passes trips nothing.
// Revert mutant: the session check in handle.
func TestLateFrameOfReplacedConnection(t *testing.T) {
	r := newRig(t, nil)
	k := &kernelLine{t: t, r: r, g: chancheck.New(r.now)}
	r.advance(chancheck.MaxLate + time.Hour)
	old, _ := k.hello()
	r.advance(time.Hour)
	late, _ := k.frame(cmd(1, "lamp", wire.VerbOn))
	k.g.Lost(k.at())
	cl, _ := k.hello()
	l := wire.Rate(wire.RateCommand)
	r.advance(time.Duration(l.Burst) * l.Every * 2)
	if exchange(old, late) {
		t.Fatal("the enforcer answered a frame of a replaced connection")
	}
	for i := range l.Burst - 1 {
		b, tk := k.frame(cmd(uint64(10+i), "lamp", wire.VerbOn))
		if !exchange(cl, b) {
			t.Fatal("connection ended")
		}
		k.g.Answered(tk, k.at())
	}
	b, tk := k.frame(cmd(99, "lamp", wire.VerbOn))
	exchange(cl, b)
	k.g.Answered(tk, k.at())
	if r.cut.trips() != 0 {
		t.Fatalf("a replaced connection's late frame counted: %v", r.cut.reasons)
	}
	if e := r.events(); !slices.ContainsFunc(e, func(e Event) bool { return e.Kind == KindFrame && strings.Contains(e.Reason, "replaced") }) {
		t.Error("the replaced connection's frame was not logged")
	}
}

// TestLostHelloCountsLate (KRN-chan-3): a hello the kernel wrote and gave
// up on reaches the enforcer just inside MaxLate, when the hello rate has
// refilled; the hellos the gate then passes trip nothing. Revert mutant:
// Lost spending a hello at the loss.
func TestLostHelloCountsLate(t *testing.T) {
	r := newRig(t, nil)
	k := &kernelLine{t: t, r: r, g: chancheck.New(r.now)}
	r.advance(chancheck.MaxLate + time.Hour)
	h, _ := wire.SignHello(wire.RoleCore, r.core, exporter)
	b, _ := k.frame(h)
	k.g.Lost(k.at())
	r.advance(chancheck.MaxLate * 9 / 10)
	stale := r.connect()
	if !exchange(stale, b) {
		t.Fatal("the enforcer refused the late hello")
	}
	stale.conn.Close()
	if n := k.helloBurst(10 * time.Minute); n == 0 {
		t.Fatal("no hello passed")
	}
	if r.cut.trips() != 0 {
		t.Fatalf("a late hello tripped the core: %v", r.cut.reasons)
	}
}

// TestRestartAfterBurst (KRN-chan-5): an earlier run of the kernel spent
// its hello burst and left one hello unanswered, which arrives just inside
// MaxLate of the restart; the new run's hellos trip nothing. Revert
// mutant: New spending the earlier run's hellos at now.
func TestRestartAfterBurst(t *testing.T) {
	r := newRig(t, nil)
	k := &kernelLine{t: t, r: r, g: chancheck.New(r.now)}
	r.advance(chancheck.MaxLate + time.Hour)
	l := wire.Rate(wire.RateHello)
	for range l.Burst - 1 {
		cl, ok := k.hello()
		if !ok {
			t.Fatal("the first run's burst was refused")
		}
		k.g.Lost(k.at())
		cl.conn.Close()
	}
	h, _ := wire.SignHello(wire.RoleCore, r.core, exporter)
	b, _ := k.frame(h)
	k.g = chancheck.New(k.at()) // the restart
	r.advance(chancheck.MaxLate * 9 / 10)
	stale := r.connect()
	if !exchange(stale, b) {
		t.Fatal("the enforcer refused the late hello")
	}
	stale.conn.Close()
	if n := k.helloBurst(20 * time.Minute); n == 0 {
		t.Fatal("no hello passed")
	}
	if r.cut.trips() != 0 {
		t.Fatalf("the restarted kernel tripped the core: %v", r.cut.reasons)
	}
}

// TestHelloCountsWhileRadioBlocks (#4508, KRN-chan-3): a hello is counted
// when it arrives, even while a radio call on the current connection holds
// the channel's lock, so a lost hello is counted inside MaxLate however
// long the radio host takes. Here the hello past the rate trips the core
// while the radio call is still blocked. Revert mutant: counting the
// hello under c.mu.
func TestHelloCountsWhileRadioBlocks(t *testing.T) {
	r := newRig(t, nil)
	l := wire.Rate(wire.RateHello)
	for range l.Burst - 1 {
		r.dial().conn.Close()
	}
	a := r.dial()
	hold, entered := make(chan struct{}), make(chan struct{}, 1)
	r.radio.mu.Lock()
	r.radio.hold, r.radio.entered = hold, entered
	r.radio.mu.Unlock()
	defer close(hold)
	go a.send(cmd(1, "lamp", wire.VerbOn))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the radio call never started")
	}
	b := r.connect()
	h, _ := wire.SignHello(wire.RoleCore, r.core, exporter)
	b.send(h)
	for deadline := time.Now().Add(5 * time.Second); r.cut.trips() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the hello past the rate was not counted while the radio call held the lock")
		}
	}
	if r.cut.trips() != 1 {
		t.Fatalf("trips %d, want 1", r.cut.trips())
	}
}
