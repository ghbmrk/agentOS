package channel

import (
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// REQ: NET-2, A18

// TestChallengeIDFreeOnlyAfterItsAnswer (#4550): the radio host's ID stays
// taken until Answer has returned, so a challenge the host sends with that
// ID while the first's answer is being handed over is refused, and the
// first's answer is never handed over as the second's. Revert mutant:
// freeing the ID when the answer is taken, before Answer runs.
func TestChallengeIDFreeOnlyAfterItsAnswer(t *testing.T) {
	inAnswer, hold := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var answers []uint64
	r := newRig(t, func(c *Config) {
		c.Answer = func(id uint64, _ []byte) {
			inAnswer <- struct{}{}
			<-hold
			mu.Lock()
			answers = append(answers, id)
			mu.Unlock()
		}
	})
	cl := r.dial()
	w := cl.challenge(r, 7)
	cl.send(wire.Challenge{Answer: true, ID: w, Data: []byte{2}})
	waitFor(t, inAnswer, "the answer handed over")
	if err := cl.tryChallenge(r, 7); !errors.Is(err, ErrOutstanding) {
		t.Fatalf("a challenge reusing the id while its answer is handed over: %v, want ErrOutstanding", err)
	}
	close(hold)
	if m, ok := cl.recv().(wire.Result); !ok || m.Code != wire.OK {
		t.Fatalf("answer result: %+v", m)
	}
	cl.challenge(r, 7) // free once Answer has returned
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(answers, []uint64{7}) {
		t.Errorf("answers %v", answers)
	}
}

// TestChallengesExpire (#4550): a challenge the core never answers is
// over ChallengeLife after it was sent, so a core that withholds
// MaxOutstanding answers holds challenges off only that long, never until
// a restart. The ID is free again, and an answer to the expired challenge,
// however late, is refused and never handed over as the answer to the
// challenge that reused its ID. Frame IDs count up from 1, so the log's
// answer lines read in the order the challenges went. Revert mutants: no
// expiry; the frame carrying the radio host's ID; the frame ID counting
// down.
func TestChallengesExpire(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	wires := map[uint64]bool{}
	var first, last uint64
	for id := range uint64(MaxOutstanding) {
		w := cl.challenge(r, id+1)
		if wires[w] || w <= last {
			t.Fatalf("frame id %d after %d: want each new and counting up", w, last)
		}
		wires[w], last = true, w
		if id == 0 {
			first = w
		}
	}
	if err := cl.tryChallenge(r, 100); !errors.Is(err, ErrBusy) {
		t.Fatalf("past the cap: %v, want ErrBusy", err)
	}
	r.advance(ChallengeLife - time.Second)
	if err := cl.tryChallenge(r, 1); !errors.Is(err, ErrOutstanding) {
		t.Fatalf("before ChallengeLife: %v, want ErrOutstanding", err)
	}
	r.advance(time.Second)
	again := cl.challenge(r, 1)
	if wires[again] || again <= last {
		t.Fatalf("the reused id's frame carries an earlier frame's id %d", again)
	}
	if c := cl.code(wire.Challenge{Answer: true, ID: first, Data: []byte{2}}); c != wire.Refused {
		t.Errorf("the expired challenge's late answer: %v, want Refused", c)
	}
	if len(r.answers) != 0 {
		t.Fatalf("an expired challenge's answer was handed over: %v", r.answers)
	}
	if c := cl.code(wire.Challenge{Answer: true, ID: again, Data: []byte{2}}); c != wire.OK {
		t.Errorf("the new challenge's answer: %v", c)
	}
	if !reflect.DeepEqual(r.answers, []uint64{1}) {
		t.Errorf("answers %v", r.answers)
	}
}

// TestLateAnswerExpires (#4550): an answer that comes ChallengeLife or more
// after its challenge is refused, and the ID is free. Revert mutant: the
// answer path not checking the challenge's life.
func TestLateAnswerExpires(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	w := cl.challenge(r, 7)
	r.advance(ChallengeLife)
	if c := cl.code(wire.Challenge{Answer: true, ID: w, Data: []byte{2}}); c != wire.Refused {
		t.Errorf("an answer ChallengeLife late: %v, want Refused", c)
	}
	if len(r.answers) != 0 {
		t.Errorf("answers %v", r.answers)
	}
	cl.challenge(r, 7)
}

// TestChallengeLifeIgnoresWallSteps (#4550, ENF-d-10, ENF-d-11): a
// challenge's life is on the rate clock, never the wall clock, so a wall
// clock stepped forward neither refuses an honest answer given at once,
// and one stepped back keeps no withheld challenge's slot past its life.
// Revert mutant: the challenge's life read on Config.Now (Security on
// #4583).
func TestChallengeLifeIgnoresWallSteps(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	w := cl.challenge(r, 7)
	r.mu.Lock()
	r.wallStep = 24 * time.Hour
	r.mu.Unlock()
	if c := cl.code(wire.Challenge{Answer: true, ID: w, Data: []byte{2}}); c != wire.OK {
		t.Errorf("an answer at once, with the wall clock stepped forward: %v, want OK", c)
	}
	r.mu.Lock()
	r.wallStep = 0
	r.mu.Unlock()
	cl.challenge(r, 8)
	r.mu.Lock()
	r.wallStep = -time.Hour
	r.mu.Unlock()
	r.advance(ChallengeLife)
	cl.challenge(r, 8) // free ChallengeLife on, though the wall clock stepped back
}

// TestChallengeEndsWithItsConnection (#4550): a challenge is over once the
// connection it was sent on is no longer the current one, so a challenge
// lost with its connection frees its ID at once, and the core cannot
// answer it on the next connection. Revert mutant: the session check in
// over.
func TestChallengeEndsWithItsConnection(t *testing.T) {
	r := newRig(t, nil)
	a := r.dial()
	w := a.challenge(r, 7)
	b := r.dial()
	if c := b.code(wire.Challenge{Answer: true, ID: w, Data: []byte{2}}); c != wire.Refused {
		t.Errorf("an answer on the next connection to the last one's challenge: %v, want Refused", c)
	}
	w2 := b.challenge(r, 7)
	if c := b.code(wire.Challenge{Answer: true, ID: w2, Data: []byte{2}}); c != wire.OK {
		t.Errorf("answer: %v", c)
	}
	if !reflect.DeepEqual(r.answers, []uint64{7}) {
		t.Errorf("answers %v", r.answers)
	}
}

// TestPausedLogIsLimited (#4558, A18): a tripped core's paused requests are
// logged up to KindPaused's bucket, then one line says the rest go
// unlogged, then nothing until the bucket refills, when logging resumes.
// The paused requests are still answered Paused, and the bucket reads the
// rate clock. Revert mutants: logging every paused request; the quiet line
// repeated; the bucket read on Config.Now.
func TestPausedLogIsLimited(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	// The line comes after the enforcer's hello is written: wait for it
	// before the trip, since a cut core's reconnect takes the bucket too
	// (#4606).
	for deadline := time.Now().Add(5 * time.Second); len(r.events()) == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the connection was not logged")
		}
	}
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	id := uint64(0)
	lines := func(from int) (paused, quiet int) {
		for _, e := range r.events()[from:] {
			switch {
			case e.Kind == KindPaused:
				quiet++
			case e.Code == wire.Paused:
				paused++
			}
		}
		return
	}
	n := len(r.events())
	for range 4 * l.Burst {
		id++
		if c := cl.code(wire.Announce{ID: id}); c != wire.Paused {
			t.Fatalf("a paused request: %v", c)
		}
	}
	if p, q := lines(n); p != l.Burst || q != 1 {
		t.Fatalf("%d paused requests logged %d lines and %d quiet lines, want %d and 1", 4*l.Burst, p, q, l.Burst)
	}
	r.advance(l.Every)
	n = len(r.events())
	for range 3 {
		id++
		cl.code(wire.Announce{ID: id})
	}
	if p, q := lines(n); p != 1 || q != 1 {
		t.Errorf("after one refill: %d lines and %d quiet lines, want 1 and 1", p, q)
	}
	// The bucket is on the rate clock: a wall clock stepped forward
	// refills nothing (ENF-d-10).
	for range 2 * l.Burst {
		id++
		cl.code(wire.Announce{ID: id})
	}
	r.mu.Lock()
	r.wallStep = 24 * time.Hour
	r.mu.Unlock()
	n = len(r.events())
	for range 5 {
		id++
		cl.code(wire.Announce{ID: id})
	}
	if p, _ := lines(n); p != 0 {
		t.Errorf("with the wall clock stepped forward: %d paused lines, want 0", p)
	}
	if r.cut.trips() != 0 {
		t.Errorf("paused requests tripped the core %d times", r.cut.trips())
	}
}

// TestAnsweredChallengeHeldWhileHandedOver (#4550): while an answer is
// being handed over, its challenge stays taken even if the connection it
// came on is replaced or its life runs out, and the same answer sent again
// on the next connection is refused, so the radio host's ID is not free
// until Answer returns. Revert mutants: the sweep dropping an answered
// challenge; the frame's ID still matching once its answer is taken.
func TestAnsweredChallengeHeldWhileHandedOver(t *testing.T) {
	inAnswer, hold := make(chan struct{}), make(chan struct{})
	r := newRig(t, func(c *Config) {
		c.Answer = func(uint64, []byte) { inAnswer <- struct{}{}; <-hold }
	})
	defer close(hold)
	a := r.dial()
	w := a.challenge(r, 7)
	a.send(wire.Challenge{Answer: true, ID: w, Data: []byte{2}})
	waitFor(t, inAnswer, "the answer handed over")
	b := r.dial()
	if c := b.code(wire.Challenge{Answer: true, ID: w, Data: []byte{2}}); c != wire.Refused {
		t.Errorf("the same answer again on the next connection: %v, want Refused", c)
	}
	r.advance(ChallengeLife)
	if err := b.tryChallenge(r, 7); !errors.Is(err, ErrOutstanding) {
		t.Fatalf("the id while its answer is handed over: %v, want ErrOutstanding", err)
	}
}

// TestFailedSendFreesOnlyItsOwn (#4550): a challenge whose frame could not
// be written frees its ID only if the ID is still that challenge's, so a
// challenge the radio host sent meanwhile with the same ID, after the
// first's connection was replaced, keeps it and gets its answer. Revert
// mutant: dropChallenge not checking the entry is its own.
func TestFailedSendFreesOnlyItsOwn(t *testing.T) {
	r := newRig(t, nil)
	a := r.dial()
	errc := make(chan error, 1)
	go func() { errc <- r.ch.Challenge(7, []byte{1}) }() // nobody reads a: the write blocks
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		r.ch.mu.Lock()
		n := len(r.ch.challenges)
		r.ch.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first challenge was not taken")
		}
	}
	b := r.dial()
	w := b.challenge(r, 7) // the first is over: its connection was replaced
	a.conn.Close()
	if err := <-errc; err == nil {
		t.Fatal("the first challenge's write did not fail")
	}
	if c := b.code(wire.Challenge{Answer: true, ID: w, Data: []byte{2}}); c != wire.OK {
		t.Errorf("the second challenge's answer: %v", c)
	}
	if !reflect.DeepEqual(r.answers, []uint64{7}) {
		t.Errorf("answers %v", r.answers)
	}
}

// waitFor waits up to 5 s for ch, so a mutant fails fast rather than by
// the test binary's timeout.
func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("waiting for %s", what)
	}
}

// TestCutCoreLinesAreLimited (#4606, A18): a tripped core that cycles
// connections, each with a frame outside the format, a frame on a
// replaced connection or a cut-off frame, logs at most KindPaused's bucket
// of lines and one quiet line, and one more line per refill; every
// malformed frame still calls Cut.Trip. At the Reflashed stage a malformed
// frame trips the core again and its line is logged with the bucket
// empty, and an open core's reconnect is always logged. Revert mutants:
// logging "core connected", the refused frame, the replaced connection's
// frame or the malformed frame unbucketed; a cut core's malformed frame
// skipping Cut.Trip; trip bucketing at Reflashed; logCut bucketing an open
// core's lines.
func TestCutCoreLinesAreLimited(t *testing.T) {
	r := newRig(t, nil)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	malformed := frameBytes(wire.TCommand, []byte{1})
	short := frameBytes(wire.TCommand, []byte{1, 2, 3})[:4]
	lines := func(from int) (logged, quiet int) {
		for _, e := range r.events()[from:] {
			if e.Kind == KindPaused {
				quiet++
			} else {
				logged++
			}
		}
		return
	}
	flood := func(rounds int) {
		for range rounds {
			if !r.dial().closed(malformed) {
				t.Fatal("a malformed frame did not end the connection")
			}
			a := r.dial()
			b := r.dial()
			a.send(wire.Announce{ID: 1})
			waitDone(t, a, "the replaced connection ended")
			b.conn.Close()
			waitDone(t, b, "the connection closed")
			c := r.dial()
			c.conn.Write(short)
			c.conn.Close()
			waitDone(t, c, "the cut-off frame ended its connection")
		}
	}
	rounds := 2 * l.Burst
	n := len(r.events())
	flood(rounds)
	if got, q := lines(n); got != l.Burst || q != 1 {
		t.Fatalf("%d rounds of a cut core's reconnects logged %d lines and %d quiet lines, want %d and 1", rounds, got, q, l.Burst)
	}
	if r.cut.trips() != rounds {
		t.Errorf("%d trips for %d malformed frames from a cut core, want each to call Cut.Trip", r.cut.trips(), rounds)
	}
	r.advance(l.Every)
	n = len(r.events())
	flood(1)
	if got, q := lines(n); got != 1 || q != 1 {
		t.Errorf("after one refill: %d lines and %d quiet lines, want 1 and 1", got, q)
	}

	// Reflashed: the malformed frame is a new trip, always logged.
	r.cut.set(Reflashed)
	trips := r.cut.trips()
	cl := r.dial() // bucketed, and the bucket is empty
	n = len(r.events())
	if !cl.closed(malformed) {
		t.Fatal("a malformed frame at the Reflashed stage did not end the connection")
	}
	if r.cut.trips() != trips+1 {
		t.Errorf("a malformed frame at the Reflashed stage: %d trips, want %d", r.cut.trips(), trips+1)
	}
	var frame int
	for _, e := range r.events()[n:] {
		if e.Kind == KindFrame && e.Code == wire.Refused {
			frame++
		}
	}
	if frame != 1 {
		t.Errorf("the trip at the Reflashed stage logged %d frame lines, want 1", frame)
	}

	// Open: every reconnect inside the hello's rate is logged, with the
	// paused bucket empty.
	r.advance(time.Hour) // refills the hello's rate, and the paused bucket
	r.cut.set(Tripped)
	cl = r.dial()
	for i := range l.Burst + 1 {
		if c := cl.code(wire.Announce{ID: uint64(i + 1)}); c != wire.Paused {
			t.Fatalf("a paused request: %v", c)
		}
	}
	cl.conn.Close()
	waitDone(t, cl, "the connection closed")
	r.cut.set(Open)
	n = len(r.events())
	for range 3 {
		cl := r.dial()
		cl.conn.Close()
		waitDone(t, cl, "the connection closed")
	}
	var hellos int
	for _, e := range r.events()[n:] {
		if e.Kind == KindHello && e.Reason == "core connected" {
			hellos++
		}
	}
	if hellos != 3 {
		t.Errorf("an open core's 3 reconnects logged %d lines, want 3", hellos)
	}
}

// waitDone waits up to 5 s for cl's connection to end on the enforcer's side.
func waitDone(t *testing.T, cl *client, what string) {
	t.Helper()
	select {
	case <-cl.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("waiting for %s", what)
	}
}

// writeThenFail is a connection's writer that, once armed, writes the
// next frame whole, waits for release, and then reports an error: a
// writer that breaks io.Writer's contract, or a deadline that fires after
// the flush (#4607).
type writeThenFail struct {
	io.ReadWriter
	armed   atomic.Bool
	wrote   chan struct{}
	release chan struct{}
}

func (w *writeThenFail) Write(b []byte) (int, error) {
	if !w.armed.CompareAndSwap(true, false) {
		return w.ReadWriter.Write(b)
	}
	n, err := w.ReadWriter.Write(b)
	if err != nil {
		return n, err
	}
	close(w.wrote)
	<-w.release
	return n, errors.New("write failed after the frame went out")
}

// TestFailedSendKeepsAnAnsweredChallenge (#4607): a challenge whose frame
// reached the core but whose write then reported an error is not freed if
// its answer was already taken: its ID stays taken until Answer returns,
// and is free once it does. Revert mutant: the send-failure path dropping
// the challenge without checking answered.
func TestFailedSendKeepsAnAnsweredChallenge(t *testing.T) {
	inAnswer, hold := make(chan struct{}), make(chan struct{})
	r := newRig(t, func(c *Config) {
		c.Answer = func(uint64, []byte) { inAnswer <- struct{}{}; <-hold }
	})
	a, b := net.Pipe()
	w := &writeThenFail{ReadWriter: b, wrote: make(chan struct{}), release: make(chan struct{})}
	cl := &client{t: t, conn: a, done: make(chan error, 1)}
	go func() { cl.done <- r.ch.Serve(w, exporter); b.Close() }()
	h, err := wire.SignHello(wire.RoleCore, r.core, exporter)
	if err != nil {
		t.Fatal(err)
	}
	cl.send(h)
	if _, ok := cl.recv().(wire.Hello); !ok {
		t.Fatal("no enforcer hello")
	}
	w.armed.Store(true)
	errc := make(chan error, 1)
	go func() { errc <- r.ch.Challenge(7, []byte{1}) }()
	m, ok := cl.recv().(wire.Challenge)
	if !ok {
		t.Fatal("no challenge frame")
	}
	waitFor(t, w.wrote, "the challenge written")
	cl.send(wire.Challenge{Answer: true, ID: m.ID, Data: []byte{2}})
	waitFor(t, inAnswer, "the answer handed over")
	close(w.release)
	if err := <-errc; err == nil {
		t.Fatal("the challenge's write did not fail")
	}
	r.ch.mu.Lock()
	held := r.ch.challenges[7] != nil
	r.ch.mu.Unlock()
	if !held {
		t.Fatal("a failed send freed a challenge whose answer was being handed over")
	}
	if err := cl.tryChallenge(r, 7); !errors.Is(err, ErrOutstanding) {
		t.Fatalf("the id while its answer is handed over: %v, want ErrOutstanding", err)
	}
	close(hold)
	if _, ok := cl.recv().(wire.Result); !ok {
		t.Fatal("no result for the answer")
	}
	if got := cl.challenge(r, 7); got == m.ID {
		t.Errorf("the id's next challenge reused frame id %d", got)
	}
}
