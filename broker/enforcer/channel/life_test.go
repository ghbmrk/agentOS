package channel

import (
	"errors"
	"reflect"
	"sync"
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
	r.cut.set(Tripped)
	cl := r.dial()
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
