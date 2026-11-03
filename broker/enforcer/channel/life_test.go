package channel

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
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

// TestReflashedLinesAreLimited (#4606, A18): at the Reflashed stage, where
// a reconnect trips nothing (countHello trips only an open core) and a
// superseded or cut-off frame never trips, the bucket is the only bound: a
// core cycling connections logs KindPaused's bucket of lines and one quiet
// line. A stage the channel does not know is cut too: its malformed frames
// each call Cut.Trip, and their lines are bucketed. Revert mutants: logCut
// bucketing only at Tripped; trip's again only at Tripped.
func TestReflashedLinesAreLimited(t *testing.T) {
	r := newRig(t, nil)
	l := DefaultLimit(KindPaused)
	short := frameBytes(wire.TCommand, []byte{1, 2, 3})[:4]
	count := func(from int) (logged, quiet int) {
		for _, e := range r.events()[from:] {
			if e.Kind == KindPaused {
				quiet++
			} else {
				logged++
			}
		}
		return
	}
	r.cut.set(Reflashed)
	for range 3 * l.Burst {
		a, b := r.dial(), r.dial()
		a.send(wire.Announce{ID: 1})
		waitDone(t, a, "the replaced connection ended")
		b.conn.Write(short)
		b.conn.Close()
		waitDone(t, b, "the cut-off frame ended its connection")
	}
	if got, q := count(0); got != l.Burst || q != 1 {
		t.Errorf("a Reflashed core cycling connections logged %d lines and %d quiet lines, want %d and 1", got, q, l.Burst)
	}
	if r.cut.trips() != 0 {
		t.Errorf("a Reflashed core's reconnects tripped it %d times", r.cut.trips())
	}

	r = newRig(t, nil)
	r.cut.set(Stage(9))
	malformed := frameBytes(wire.TCommand, []byte{1})
	rounds := 2 * l.Burst
	var frames int
	for range rounds {
		cl := r.dial()
		if !cl.closed(malformed) {
			t.Fatal("a malformed frame did not end the connection")
		}
		r.cut.set(Stage(9)) // the fake cut's Trip moves it to Tripped
	}
	for _, e := range r.events() {
		if e.Kind == KindFrame {
			frames++
		}
	}
	if frames > l.Burst {
		t.Errorf("a core at an unknown stage logged %d malformed-frame lines, want at most %d", frames, l.Burst)
	}
	if r.cut.trips() != rounds {
		t.Errorf("%d trips for %d malformed frames at an unknown stage", r.cut.trips(), rounds)
	}
}

// TestLinesBucketedWhileATripIsInFlight (#4606, ENF-d-7): from the moment
// the channel decides a trip until Cut.Trip returns, the core counts as
// cut for its log lines too, so reconnects made while a slow cut runs are
// bucketed. Revert mutant: logCut reading Cut.Stage, not stage.
func TestLinesBucketedWhileATripIsInFlight(t *testing.T) {
	r := newRig(t, nil)
	l := DefaultLimit(KindPaused)
	hold, entered := make(chan struct{}), make(chan struct{}, 1)
	r.cut.mu.Lock()
	r.cut.hold, r.cut.entered = hold, entered
	r.cut.mu.Unlock()
	a := r.dial()
	go a.conn.Write(frameBytes(wire.TCommand, []byte{1}))
	waitFor(t, entered, "the trip in flight")
	n := len(r.events())
	for range 2 * l.Burst {
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
	close(hold)
	waitDone(t, a, "the tripping connection ended")
	if hellos != l.Burst {
		t.Errorf("%d reconnects while a trip was in flight logged %d lines, want %d", 2*l.Burst, hellos, l.Burst)
	}
}

// failFirstWrite is a connection's writer whose next write, once armed,
// fails with nothing written.
type failFirstWrite struct {
	io.ReadWriter
	armed atomic.Bool
}

func (w *failFirstWrite) Write(b []byte) (int, error) {
	if w.armed.CompareAndSwap(true, false) {
		return 0, errors.New("write failed")
	}
	return w.ReadWriter.Write(b)
}

// TestFailedSendFreesAnUnansweredChallenge (#4607, ENF-d-11): a challenge
// whose write failed before any answer came is freed at once, so the radio
// host may retry its ID. Revert mutant: the send-failure path never
// dropping.
func TestFailedSendFreesAnUnansweredChallenge(t *testing.T) {
	r := newRig(t, nil)
	a, b := net.Pipe()
	w := &failFirstWrite{ReadWriter: b}
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
	if err := r.ch.Challenge(7, []byte{1}); err == nil {
		t.Fatal("the challenge's write did not fail")
	}
	r.ch.mu.Lock()
	held, wires := r.ch.challenges[7] != nil, len(r.ch.byWire)
	r.ch.mu.Unlock()
	if held || wires != 0 {
		t.Fatalf("a failed send left its unanswered challenge taken (%v, %d frame ids)", held, wires)
	}
	w2 := cl.challenge(r, 7)
	if c := cl.code(wire.Challenge{Answer: true, ID: w2, Data: []byte{2}}); c != wire.OK {
		t.Errorf("the retried challenge's answer: %v", c)
	}
}

// TestCutCoreDropCount (#4657, A18): the lines a cut core's flood loses
// past KindPaused's bucket are counted, and the next line logged carries
// the count, whether the bucket refilled or the owner's restore came
// first, so the owner's record keeps how much a cut core tried. The bound
// is unchanged: the count rides on a line that is logged anyway. Revert
// mutants: no count; the count not reset once carried; a dropped line
// left uncounted (the paused request, the reconnect or the malformed
// frame); the count carried only by a bucketed line.
func TestCutCoreDropCount(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	waitLines(t, r, 1)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	malformed := frameBytes(wire.TCommand, []byte{1})
	// flood sends 4 bucketfuls of paused requests, then a reconnect with
	// a frame outside the format, all dropped once the bucket is empty.
	flood := func(cl *client, from uint64) {
		for id := range uint64(4 * l.Burst) {
			cl.code(wire.Announce{ID: from + id})
		}
		if !r.dial().closed(malformed) {
			t.Fatal("a malformed frame did not end the connection")
		}
	}
	carried := func(from int) (counts []int) {
		for _, e := range r.events()[from:] {
			if e.Dropped != 0 {
				counts = append(counts, e.Dropped)
			}
		}
		return
	}

	// The bucket refills: the next line logged, the cut core's next
	// reconnect, carries the count.
	n := len(r.events())
	flood(cl, 1)
	want := 3*l.Burst + 2 // the requests past the bucket, the reconnect and its frame
	if got := carried(n); got != nil {
		t.Fatalf("lines carried counts %v before any was logged after the drops", got)
	}
	r.advance(l.Every)
	n = len(r.events())
	cl = r.dial()
	waitLines(t, r, n+1)
	ev := r.events()[n]
	if ev.Dropped != want {
		t.Fatalf("the line after the refill carried %d dropped lines, want %d", ev.Dropped, want)
	}
	if line := ev.Line(); !strings.Contains(line, fmt.Sprintf("(%d of a cut core's lines dropped unlogged before this one)", want)) {
		t.Errorf("the owner's line does not show the count: %q", line)
	}
	if got := carried(n + 1); got != nil {
		t.Errorf("the count was carried again: %v", got)
	}

	// The owner restores the core before the bucket refills: the open
	// core's reconnect, logged outside the bucket, carries the count.
	n = len(r.events())
	flood(cl, 1000)
	want = 4*l.Burst + 2 // the reconnect after the refill took its one token
	r.cut.set(Open)
	n2 := len(r.events())
	cl = r.dial()
	waitLines(t, r, n2+1)
	if got := carried(n); len(got) != 1 || got[0] != want {
		t.Errorf("after the restore the lines carried counts %v, want [%d]", got, want)
	}
	cl.conn.Close()
	waitDone(t, cl, "the connection closed")
}

// waitLines waits up to 5 s for r to hold n log lines; a connection's
// line lands after the enforcer's hello is written.
func waitLines(t *testing.T, r *rig, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); len(r.events()) < n; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d log lines, want %d", len(r.events()), n)
		}
	}
}

// TestDropCountEdges (#4683, A18): the count of a cut core's dropped lines
// counts only lines the bucket dropped and lands only on the core's own
// lines. A failed hello, logged on its own bucket while a count is
// pending, neither carries the count nor adds to it; at Reflashed the
// re-trip's line, always logged, is not counted and carries the count.
// Revert mutants: a failed hello's line carrying the count; a failed hello
// counted; the Reflashed re-trip's line counted as dropped or bucketed.
func TestDropCountEdges(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	waitLines(t, r, 1)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	for id := range uint64(4 * l.Burst) {
		cl.code(wire.Announce{ID: id + 1})
	}
	want := 3 * l.Burst

	f, err := wire.Encode(wire.ToEnforcer, wire.Announce{ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	n := len(r.events())
	if !r.connect().closed(frameBytes(f.Type, f.Payload)) {
		t.Fatal("a frame before the hello was not dropped")
	}
	ev := r.events()[n:]
	if len(ev) != 1 || ev[0].Kind != KindHello || ev[0].Code != wire.Refused {
		t.Fatalf("a failed hello logged %+v, want its one line", ev)
	}
	if ev[0].Dropped != 0 {
		t.Errorf("a failed hello's line carried the cut core's count %d", ev[0].Dropped)
	}

	// Reflashed: the reconnect is bucketed and dropped (one more), and the
	// malformed frame is a new trip, logged with the count.
	r.cut.set(Reflashed)
	n = len(r.events())
	if !r.dial().closed(frameBytes(wire.TCommand, []byte{1})) {
		t.Fatal("a malformed frame did not end the connection")
	}
	want++
	var got []Event
	for _, e := range r.events()[n:] {
		if e.Kind == KindFrame {
			got = append(got, e)
		}
	}
	if len(got) != 1 {
		t.Fatalf("the Reflashed core's malformed frame logged %d lines, want 1", len(got))
	}
	if got[0].Dropped != want {
		t.Errorf("the re-trip's line carried %d dropped lines, want %d", got[0].Dropped, want)
	}
}

// TestDropCountRestart (#4683, #4710, ENF-d-4): the count lives in the
// channel's memory, so a restart of the channel loses a count no line has
// carried yet; the quiet line, logged last before the restart, records
// that lines were dropped, and the restarted channel's first line carries
// none. Revert mutants: the quiet line not logged; a drop not counted.
func TestDropCountRestart(t *testing.T) {
	var cfg Config
	r := newRig(t, func(c *Config) { cfg = *c })
	cl := r.dial()
	waitLines(t, r, 1)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	for id := range uint64(2 * l.Burst) {
		cl.code(wire.Announce{ID: id + 1})
	}
	// What the restart loses is the pending count; what the record keeps
	// is the quiet line, the last line logged, and no line carried a count
	// (#4710).
	evs := r.events()
	quiet := 0
	for _, e := range evs {
		if e.Kind == KindPaused {
			quiet++
		}
		if e.Dropped != 0 {
			t.Errorf("a line before the restart carried %d dropped lines", e.Dropped)
		}
	}
	if quiet != 1 || evs[len(evs)-1].Kind != KindPaused {
		t.Fatalf("before the restart: %d quiet lines, last line %+v; want 1, the quiet line last", quiet, evs[len(evs)-1])
	}
	r.ch.mu.Lock()
	pending := r.ch.dropped
	r.ch.mu.Unlock()
	if pending != l.Burst {
		t.Fatalf("%d dropped lines pending before the restart, want %d", pending, l.Burst)
	}
	ch, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.ch = ch
	n := len(r.events())
	cl = r.dial()
	waitLines(t, r, n+1)
	if e := r.events()[n]; e.Dropped != 0 {
		t.Errorf("the restarted channel's first line carried %d dropped lines, want 0", e.Dropped)
	}
	cl.conn.Close()
	waitDone(t, cl, "the connection closed")
}

// TestEveryEventFieldRendered (#4683, ENF-d-4, ENF-d-8): the owner's line
// and the detail view show every Event field but At, which slice l's
// renderer shows in the configured zone. A field a render drops, such as
// Dropped, breaks the invariant that the logged lines plus the sum of
// Dropped equal what the cut core sent. The fields are CheckSink's samples,
// so a new field fails here until it is rendered, and fails every sink's
// check until setField can set it.
func TestEveryEventFieldRendered(t *testing.T) {
	samples, err := eventSamples()
	if err != nil {
		t.Fatal(err)
	}
	var zero Event
	for _, s := range samples {
		if s.field == "Event.At" {
			continue
		}
		if s.e.Line() == zero.Line() || s.e.Detail() == zero.Detail() {
			t.Errorf("%s is not rendered: %q", s.field, s.e.Line())
		}
	}
}

// TestEventSamples (#4791 Security 2): CheckSink and
// TestEveryEventFieldRendered take their samples from eventSamples, so
// this pins them: each of a field's values in a sample with that field
// alone set, then samples with every field set, one for each value of the
// field that has most. Revert mutants: the one-field samples dropped; a
// one-field sample with another field set; the all-fields samples dropped.
func TestEventSamples(t *testing.T) {
	samples, err := eventSamples()
	if err != nil {
		t.Fatal(err)
	}
	typ := reflect.TypeFor[Event]()
	i, most := 0, 0
	for f := range typ.NumField() {
		vs, err := fieldValues(typ.Field(f).Type)
		if err != nil {
			t.Fatal(err)
		}
		if len(vs) < 2 {
			t.Errorf("Event.%s has %d sample values, want at least 2", typ.Field(f).Name, len(vs))
		}
		for j := range vs {
			for k := range j {
				if vs[j].Equal(vs[k]) {
					t.Errorf("Event.%s has the sample value %v twice", typ.Field(f).Name, vs[j])
				}
			}
		}
		most = max(most, len(vs))
		for range vs {
			if i >= len(samples) {
				t.Fatalf("%d samples, too few", len(samples))
			}
			v := reflect.ValueOf(samples[i].e)
			for g := range typ.NumField() {
				if v.Field(g).IsZero() != (g != f) {
					t.Errorf("sample %d (%s): Event.%s set %v", i, samples[i].field, typ.Field(g).Name, !v.Field(g).IsZero())
				}
			}
			i++
		}
	}
	if len(samples) != i+most {
		t.Fatalf("%d samples, want %d with one field set and %d with every field", len(samples), i, most)
	}
	// The j-th every-field sample sets each field to its j-th value, or
	// its last where it has fewer, so every value meets every other field
	// set (#4791 L3 round 2).
	for j, s := range samples[i:] {
		v := reflect.ValueOf(s.e)
		for g := range typ.NumField() {
			vs, _ := fieldValues(typ.Field(g).Type)
			if want := vs[min(j, len(vs)-1)]; !v.Field(g).Equal(want) {
				t.Errorf("every-field sample %d has Event.%s %v, want %v", j, typ.Field(g).Name, v.Field(g), want)
			}
		}
	}
}

// TestCheckSink (#4709, A18, ENF-d-4): a sink that stores Event as JSON
// keeps every field, and CheckSink refuses a sink that loses any one field
// (each zeroed in turn: Dropped among them), one that keeps At only to the
// second, one that narrows a field or writes a constant into it, one that
// joins two fields or cuts a name, one that loses a field only when it is
// set alone, and one that fails to store. Slice l's daemon sink runs the same
// check on its own storage (briefs/ENF.md ENF-l). Revert mutants: a sample
// left unchecked; At compared by ==; the all-fields sample missing; any
// extreme, long or second value dropped from fieldValues.
func TestCheckSink(t *testing.T) {
	asJSON := func(e Event) (Event, error) {
		b, err := json.Marshal(e)
		if err != nil {
			return Event{}, err
		}
		var got Event
		return got, json.Unmarshal(b, &got)
	}
	if err := CheckSink(asJSON); err != nil {
		t.Fatalf("a JSON sink: %v", err)
	}
	typ := reflect.TypeFor[Event]()
	for i := range typ.NumField() {
		lose := func(e Event) (Event, error) {
			got, err := asJSON(e)
			f := reflect.ValueOf(&got).Elem().Field(i)
			f.Set(reflect.Zero(f.Type()))
			return got, err
		}
		if err := CheckSink(lose); err == nil || !strings.Contains(err.Error(), "lost") {
			t.Errorf("a sink that loses Event.%s passed: %v", typ.Field(i).Name, err)
		}
	}
	seconds := func(e Event) (Event, error) {
		e.At = e.At.Truncate(time.Second)
		return e, nil
	}
	if err := CheckSink(seconds); err == nil {
		t.Error("a sink that keeps At only to the second passed")
	}
	// A zone the sink does not keep by name is the same instant.
	inUTC := func(e Event) (Event, error) {
		e.At = e.At.UTC()
		return e, nil
	}
	if err := CheckSink(inUTC); err != nil {
		t.Errorf("a sink that keeps At in UTC: %v", err)
	}
	// A sink that narrows a field, or writes a constant into it, gets the
	// small samples back whole; only the extreme ones and the second kind
	// and code catch it (#4791 L3).
	narrowed := map[string]func(*Event){
		"ID through uint32":     func(e *Event) { e.ID = uint64(uint32(e.ID)) },
		"ID through float64":    func(e *Event) { e.ID = uint64(float64(e.ID)) },
		"Dropped through int8":  func(e *Event) { e.Dropped = int(int8(e.Dropped)) },
		"Dropped through int32": func(e *Event) { e.Dropped = int(int32(e.Dropped)) },
		"Dropped kept unsigned": func(e *Event) { e.Dropped = max(e.Dropped, 0) },
		"every Kind as paused": func(e *Event) {
			if e.Kind != "" {
				e.Kind = KindPaused
			}
		},
		"every Code as paused": func(e *Event) {
			if e.Code != 0 {
				e.Code = wire.Paused
			}
		},
		"Dropped capped at 2^31-1": func(e *Event) { e.Dropped = min(e.Dropped, math.MaxInt32) },
		"Reason cut to 64 bytes":   func(e *Event) { e.Reason = e.Reason[:min(len(e.Reason), 64)] },
		"Device as ASCII":          func(e *Event) { e.Device = strings.Map(func(r rune) rune { return min(r, '?') }, e.Device) },
		"At kept to microseconds":  func(e *Event) { e.At = e.At.Truncate(time.Microsecond) },
		"At kept only to year 3000": func(e *Event) {
			if e.At.Year() > 3000 {
				e.At = time.Time{}
			}
		},
	}
	for name, narrow := range narrowed {
		keep := func(e Event) (Event, error) {
			got, err := asJSON(e)
			narrow(&got)
			return got, err
		}
		if err := CheckSink(keep); err == nil {
			t.Errorf("a sink with %s passed", name)
		}
	}
	// Sinks that lose a core's real values (#4791 Security): Device and
	// Other joined by a separator a signed ID may hold and split back; a
	// count kept in a byte; a name cut to a fixed column.
	joined := func(e Event) (Event, error) {
		e.Device, e.Other, _ = strings.Cut(e.Device+"|"+e.Other, "|")
		return e, nil
	}
	if err := CheckSink(joined); err == nil {
		t.Error("a sink that joins Device and Other with | passed")
	}
	if err := CheckSink(func(e Event) (Event, error) { e.Dropped = int(int8(e.Dropped)); return e, nil }); err == nil {
		t.Error("a sink that keeps Dropped in a byte passed")
	}
	if err := CheckSink(func(e Event) (Event, error) { e.Device = e.Device[:min(len(e.Device), 16)]; return e, nil }); err == nil {
		t.Error("a sink that keeps 16 bytes of Device passed")
	}
	// A sink that loses a field only when it is the only one set.
	alone := func(e Event) (Event, error) {
		if (e == Event{Dropped: e.Dropped}) {
			e.Dropped = 0
		}
		return e, nil
	}
	if err := CheckSink(alone); err == nil {
		t.Error("a sink that loses Dropped on a line with no other field passed")
	}
	// A sink that narrows a field only while another is set: only an
	// every-field sample past the first values catches it.
	coupled := func(e Event) (Event, error) {
		if e.Code != 0 {
			e.Dropped = int(int8(e.Dropped))
		}
		return e, nil
	}
	if err := CheckSink(coupled); err == nil {
		t.Error("a sink that keeps Dropped in a byte on a line with a Code passed")
	}
	// The failing sink hands back what it was given, so only its error
	// can fail it.
	failing := func(e Event) (Event, error) { return e, errors.New("disk full") }
	if err := CheckSink(failing); err == nil {
		t.Error("a sink that failed to store passed")
	}
	// Only the sample with every field set catches a sink that keeps one
	// field only while another is zero.
	exclusive := func(e Event) (Event, error) {
		if e.Code != 0 {
			e.Dropped = 0
		}
		return e, nil
	}
	if err := CheckSink(exclusive); err == nil {
		t.Error("a sink that drops Dropped from a line with a Code passed")
	}
}

// TestDropCountInvariant (#4707, A18, ENF-d-4): over a mixed sequence from
// a cut core (paused requests, reconnects, refused, replaced and malformed
// frames, a Reflashed re-trip, refills between), the core's lines logged
// plus the sum of Dropped equal every line the core caused, once a last
// line carries what is pending; a failed hello in each round, not the
// core's, neither takes the count nor adds to it (#4723). Revert mutants:
// any one kind of line dropped uncounted or counted when logged; a failed
// hello's line carrying the count.
func TestDropCountInvariant(t *testing.T) {
	r := newRig(t, nil)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	malformed := frameBytes(wire.TCommand, []byte{1})
	short := frameBytes(wire.TCommand, []byte{1, 2, 3})[:4]
	sent, id := 0, uint64(0)
	for round := range 6 {
		cl := r.dial() // "core connected"
		for range 2 * l.Burst {
			id++
			cl.code(wire.Announce{ID: id}) // paused
		}
		sent += 1 + 2*l.Burst
		a, b := r.dial(), r.dial()
		a.send(wire.Announce{ID: 1}) // a frame on a replaced connection
		waitDone(t, a, "the replaced connection ended")
		b.conn.Close()
		waitDone(t, b, "the connection closed")
		sent += 3
		c := r.dial()
		c.conn.Write(short) // a refused, cut-off frame
		c.conn.Close()
		waitDone(t, c, "the cut-off frame ended its connection")
		sent += 2
		if round == 3 {
			r.cut.set(Reflashed) // the malformed frame below is a new trip
		}
		if !r.dial().closed(malformed) {
			t.Fatal("a malformed frame did not end the connection")
		}
		sent += 2
		failHello(t, r) // not the core's: neither counted nor carrying the count (#4723)
		r.advance(time.Duration(round) * l.Every)
	}
	r.advance(time.Duration(l.Burst) * l.Every)
	n := len(r.events())
	last := r.dial() // carries what is pending
	waitLines(t, r, n+1)
	sent++
	logged, dropped, failed := 0, 0, 0
	for _, e := range r.events() {
		if coreLine(e) {
			logged++
		} else if e.Kind != KindPaused {
			failed++
			if e.Dropped != 0 {
				t.Errorf("a failed hello's line %+v carried the cut core's count", e)
			}
		}
		dropped += e.Dropped
	}
	if failed != 6 {
		t.Errorf("%d failed hellos logged, want the 6 sent", failed)
	}
	if logged+dropped != sent {
		t.Errorf("%d lines logged plus %d dropped, want the %d the core caused", logged, dropped, sent)
	}
	if dropped == 0 {
		t.Error("nothing was dropped: the sequence did not reach the bound")
	}
	last.conn.Close()
	waitDone(t, last, "the connection closed")
}

// TestHelloTripCarriesCount (#4708, ENF-d-4): a count pending when the
// owner restores the core lands on the core's next line even when that is
// a hello-burst trip, which is logged through the channel's log.
// Revert mutant: the hello trip's line logged around c.log.
func TestHelloTripCarriesCount(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	waitLines(t, r, 1)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	for id := range uint64(2 * l.Burst) {
		cl.code(wire.Announce{ID: id + 1})
	}
	r.cut.set(Open)
	r.advance(wire.Rate(wire.RateHello).Every * time.Duration(wire.Rate(wire.RateHello).Burst))
	h, _ := wire.SignHello(wire.RoleCore, r.core, exporter)
	for r.cut.trips() == 0 {
		// Each hello is counted as it is read, and the pipe is closed
		// before the enforcer's hello is read back, so that write fails
		// and Serve returns before it logs "core connected". No reconnect
		// before the trip logs a line of its own, so none takes the count:
		// the first line the count can land on is the trip's (#4722).
		// Read the enforcer's hello here and the count lands on the first
		// reconnect's line instead.
		b := r.connect()
		b.send(h)
		b.conn.Close()
		waitDone(t, b, "the connection ended")
	}
	var trip *Event
	for _, e := range r.events() {
		if e.Kind == KindTrip {
			trip = &e
		}
		if e.Dropped != 0 && e.Kind != KindTrip {
			t.Errorf("the count landed on %+v, not the trip line", e)
		}
	}
	if trip == nil || trip.Dropped != l.Burst {
		t.Fatalf("the hello trip line %+v, want it to carry %d dropped lines", trip, l.Burst)
	}
}

// TestSilentCoreCountWaits (#4706, #4725, ENF-d-4): the channel has no
// timer, so a cut core that goes silent after a burst leaves its count
// pending with no line, however long it stays silent, and its next line,
// such as the next hello a live kernel sends, carries the whole count.
// Nothing here waits on the wall clock: the failed hello after the day is a
// sync point through the channel's lock and log, so any line the channel
// queued for the day lands before it, and TestNoTimer rules out a line
// queued later by a timer or goroutine of the channel's own. Revert
// mutants: the count dropped once the bucket refills; the count reset by
// time; a line flushed on the first lock after the day.
func TestSilentCoreCountWaits(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	waitLines(t, r, 1)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	for id := range uint64(2 * l.Burst) {
		cl.code(wire.Announce{ID: id + 1})
	}
	n := len(r.events())
	r.advance(24 * time.Hour)
	failHello(t, r)
	if ev := r.events()[n:]; len(ev) != 1 || ev[0].Code != wire.Refused || ev[0].Dropped != 0 {
		t.Fatalf("a silent core's day then a failed hello logged %+v, want the failed hello's line alone, with no count", ev)
	}
	r.ch.mu.Lock()
	pending := r.ch.dropped
	r.ch.mu.Unlock()
	if pending != l.Burst {
		t.Fatalf("%d dropped lines pending after the day, want %d", pending, l.Burst)
	}
	cl = r.dial()
	waitLines(t, r, n+2)
	if e := r.events()[n+1]; e.Kind != KindHello || e.Dropped != l.Burst {
		t.Errorf("the next hello's line %+v, want it to carry %d dropped lines", e, l.Burst)
	}
	cl.conn.Close()
	waitDone(t, cl, "the connection closed")
	if got := len(r.events()); got != n+2 {
		t.Errorf("%d lines after the day, want 2", got-n)
	}
}

// failHello drops a connection whose first frame is not a hello, and
// returns once the channel has logged it: a failed hello's line goes
// through the channel's lock and log and is not the core's (#4683).
func failHello(t *testing.T, r *rig) {
	t.Helper()
	f, err := wire.Encode(wire.ToEnforcer, wire.Announce{ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !r.connect().closed(frameBytes(f.Type, f.Payload)) {
		t.Fatal("a frame before the hello was not dropped")
	}
}

// coreLine reports whether e is a line the core caused: not the quiet
// line or the restore's (KindPaused), nor a failed hello's (#4683).
func coreLine(e Event) bool {
	return e.Kind != KindPaused && e.Kind != KindPreAuth && !(e.Kind == KindHello && e.Code == wire.Refused)
}

// TestNoTimer (#4725, ENF-d-4): the channel's code starts no goroutine and
// arms no timer, so every line it logs is queued while it handles a call:
// nothing logs while the core is silent, and a test's sync point through
// the channel orders every line before it. Each file's import names are
// resolved, so a renamed import is caught, and a dot or blank import of a
// package that can call back later fails. Revert mutants: a goroutine; a
// timer under a renamed import; context.AfterFunc or a context deadline;
// runtime.SetFinalizer (#4735 L3); any of these in a package of this
// module the channel imports, directly or not, every file of it read
// whatever its build constraint (#4740).
func TestNoTimer(t *testing.T) {
	banned := map[string]map[string]bool{
		"time":    {"AfterFunc": true, "After": true, "NewTimer": true, "NewTicker": true, "Tick": true, "Sleep": true},
		"context": {"AfterFunc": true, "WithTimeout": true, "WithDeadline": true, "WithTimeoutCause": true, "WithDeadlineCause": true},
		"runtime": {"SetFinalizer": true, "AddCleanup": true},
	}
	// The channel's package and every package of this module it imports,
	// directly or through another, since a timer started there runs for
	// the channel too (#4740, from #4735 Security). Packages outside the
	// module are the standard library's, which banned covers by name.
	const module = "github.com/ghbmrk/agentos/broker/"
	dirs, seen := []string{"."}, map[string]bool{".": true}
	fset, files := token.NewFileSet(), 0
	for len(dirs) > 0 {
		dir := dirs[0]
		dirs = dirs[1:]
		names, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files++
			for _, im := range f.Imports {
				path, _ := strconv.Unquote(im.Path.Value)
				if rest, ok := strings.CutPrefix(path, module); ok {
					if d := filepath.Join("..", "..", filepath.FromSlash(rest)); !seen[d] {
						seen[d] = true
						dirs = append(dirs, d)
					}
				}
			}
			checkNoTimer(t, fset, f, banned)
		}
	}
	for _, want := range []string{"../../enforcer/wire", "../../enforcer/policy", "../../kernel/key"} {
		if !seen[want] {
			t.Errorf("the walk never reached %s", want)
		}
	}
	if files == 0 {
		t.Fatal("no source files parsed")
	}
}

// checkNoTimer reports f's goroutines and its uses of banned, by the
// names f imports them under.
func checkNoTimer(t *testing.T, fset *token.FileSet, f *ast.File, banned map[string]map[string]bool) {
	t.Helper()
	local := map[string]string{} // import name in this file -> path
	for _, im := range f.Imports {
		path, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if banned[path] == nil {
			continue
		}
		n := path
		if im.Name != nil {
			n = im.Name.Name
		}
		if n == "." || n == "_" {
			t.Errorf("%s imports %q as %s, which this test cannot follow", fset.Position(im.Pos()), path, n)
			continue
		}
		local[n] = path
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.GoStmt:
			t.Errorf("%s starts a goroutine", fset.Position(n.Pos()))
		case *ast.SelectorExpr:
			if x, ok := n.X.(*ast.Ident); ok && banned[local[x.Name]][n.Sel.Name] {
				t.Errorf("%s calls %s.%s", fset.Position(n.Pos()), local[x.Name], n.Sel.Name)
			}
		}
		return true
	})
}

// TestFlushAtRestore (#4726, ENF-d-4): the owner's restore calls Flush,
// whose one line carries the count pending, so the record has it at the
// restore, not at the core's next line; the core's next line then carries
// none, a Flush with nothing pending logs nothing, and a later cut's drops
// get their own quiet line. Revert mutants: Flush's line not carrying the
// count; Flush logging with nothing pending; the quiet not ended.
func TestFlushAtRestore(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	waitLines(t, r, 1)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	id := uint64(0)
	burst := func() {
		for range 2 * l.Burst {
			id++
			cl.code(wire.Announce{ID: id})
		}
	}
	burst()
	r.cut.set(Open)
	n := len(r.events())
	r.ch.Flush()
	ev := r.events()[n:]
	if len(ev) != 1 || ev[0].Kind != KindPaused || ev[0].Dropped != l.Burst {
		t.Fatalf("Flush at the restore logged %+v, want one line carrying %d dropped lines", ev, l.Burst)
	}
	r.ch.Flush()
	if got := len(r.events()); got != n+1 {
		t.Errorf("a Flush with nothing pending logged %d lines", got-n-1)
	}
	cl.conn.Close()
	waitDone(t, cl, "the connection closed")
	cl = r.dial()
	waitLines(t, r, n+2)
	if e := r.events()[n+1]; e.Dropped != 0 {
		t.Errorf("the core's next line after the restore carried %d dropped lines", e.Dropped)
	}
	r.cut.set(Tripped)
	n = len(r.events())
	burst()
	quiet := 0
	for _, e := range r.events()[n:] {
		if e.Kind == KindPaused {
			quiet++
		}
	}
	if quiet != 1 {
		t.Errorf("the next cut's drops logged %d quiet lines, want 1", quiet)
	}
	cl.conn.Close()
	waitDone(t, cl, "the connection closed")
}

// TestFlushOnlyWhenOpen (#4740, ENF-d-4): a Flush called while the core is
// still cut, at Tripped or at Reflashed, logs nothing, ends no quiet and
// keeps the count, so the record never claims a restore that did not
// happen; the Flush after the cut returns to Open logs the whole count.
// Revert mutants: Flush not checking the stage; the check placed after the
// quiet is ended.
func TestFlushOnlyWhenOpen(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	waitLines(t, r, 1)
	r.cut.set(Tripped)
	l := DefaultLimit(KindPaused)
	id := uint64(0)
	burst := func() {
		for range 2 * l.Burst {
			id++
			cl.code(wire.Announce{ID: id})
		}
	}
	burst()
	for _, st := range []Stage{Tripped, Reflashed} {
		r.cut.set(st)
		n := len(r.events())
		r.ch.Flush()
		if ev := r.events()[n:]; len(ev) != 0 {
			t.Fatalf("Flush at stage %v logged %+v", st, ev)
		}
		burst() // still quiet: no second quiet line
		for _, e := range r.events()[n:] {
			if e.Kind == KindPaused {
				t.Fatalf("Flush at stage %v ended the quiet: %+v", st, e)
			}
		}
	}
	r.cut.set(Open)
	n := len(r.events())
	r.ch.Flush()
	ev := r.events()[n:]
	// The first burst's own lines over the bucket, then two whole bursts.
	if want := l.Burst + 2*2*l.Burst; len(ev) != 1 || ev[0].Dropped != want {
		t.Fatalf("Flush after the restore logged %+v, want one line carrying %d dropped lines", ev, want)
	}
	cl.conn.Close()
	waitDone(t, cl, "the connection closed")
}

// TestPausedLinesCarryPaused (#4740): every KindPaused line, the quiet line
// and the restore's, carries Code wire.Paused, so the owner's log reads
// them alike. Revert mutant: either line built without the code.
func TestPausedLinesCarryPaused(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	waitLines(t, r, 1)
	r.cut.set(Tripped)
	for id := range uint64(2 * DefaultLimit(KindPaused).Burst) {
		cl.code(wire.Announce{ID: id + 1})
	}
	r.cut.set(Open)
	r.ch.Flush()
	quiet, restore := 0, 0
	for _, e := range r.events() {
		if e.Kind != KindPaused {
			continue
		}
		if e.Code != wire.Paused {
			t.Errorf("a paused line carries code %v: %q", e.Code, e.Line())
		}
		if e.Dropped != 0 {
			restore++
		} else {
			quiet++
		}
	}
	if quiet != 1 || restore != 1 {
		t.Errorf("logged %d quiet and %d restore lines, want one of each", quiet, restore)
	}
	cl.conn.Close()
	waitDone(t, cl, "the connection closed")
}

// TestFlushDuringTrip (#4791 Security 3, ENF-d-4, ENF-d-7): a Flush while
// a trip is decided but Cut.Trip has not returned, when the cut still reads
// Open, logs no restore, keeps the quiet and keeps the count, which the
// Flush after the owner's restore logs whole. Revert mutant: Flush reading
// Cut.Stage instead of the channel's stage, which counts the trip in
// progress.
func TestFlushDuringTrip(t *testing.T) {
	r := newRig(t, nil)
	a := r.dial()
	hold, entered := make(chan struct{}), make(chan struct{}, 1)
	r.cut.mu.Lock()
	r.cut.hold, r.cut.entered = hold, entered
	r.cut.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { close(hold) }) }
	defer release()
	tripped := make(chan struct{})
	go func() { // a request burst at Open: the last one trips the core
		defer close(tripped)
		for id := uint64(1); a.code(wire.Announce{ID: id}) == wire.OK; id++ {
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no trip")
	}
	l := DefaultLimit(KindPaused)
	b := r.dial() // "core connected", under KindPaused's bucket
	id := uint64(1000)
	burst := func() {
		for range 2 * l.Burst {
			id++
			if c := b.code(wire.Announce{ID: id}); c != wire.Paused {
				t.Fatalf("a request while the core is cut: %v, want Paused", c)
			}
		}
	}
	burst()
	n := len(r.events())
	r.ch.Flush()
	if ev := r.events()[n:]; len(ev) != 0 {
		t.Fatalf("Flush during a trip in progress logged %+v", ev)
	}
	release()
	<-tripped
	burst() // still quiet: no second quiet line
	r.cut.set(Open)
	r.ch.Flush()
	var paused []Event
	for _, e := range r.events()[n:] {
		if e.Kind == KindPaused {
			paused = append(paused, e)
		}
	}
	// One restore line, no quiet line, and the count kept: at least the
	// second burst, all of it past the drained bucket.
	if len(paused) != 1 || paused[0].Dropped < 2*l.Burst {
		t.Fatalf("after a Flush during a trip in progress and one at the restore: %+v, want one restore line carrying at least %d", paused, 2*l.Burst)
	}
	a.conn.Close()
	b.conn.Close()
	waitDone(t, b, "the connection closed")
}
