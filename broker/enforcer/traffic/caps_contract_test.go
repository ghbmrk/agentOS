package traffic

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/kernel/capgate"
)

// REQ: NET-2, KRN-12, A18

// sim is the shared count-read contract run end to end (D-255, #4174 with
// #4173/#4374): the enforcer's Counter counts what a core delivers, its
// Counts travel in the shared format's one encoding, and the kernel's
// capgate.Gate decides each send from them. Both run on one clock, which
// moves only by the steps the test names.
type sim struct {
	t       *testing.T
	clk     *clock
	enf     *Counter
	gate    *capgate.Gate
	sent    map[netip.Addr]uint64
	tripped []Overrun
}

func newSim(t *testing.T, caps Caps) *sim {
	clk := &clock{noon}
	s := &sim{t: t, clk: clk, enf: NewCounter(clk.now, caps), gate: capgate.New(clk.now), sent: map[netip.Addr]uint64{}}
	return s
}

// deliver is bytes the firewall counts on the way to addr, read at once.
func (s *sim) deliver(addr netip.Addr, n uint64) {
	s.sent[addr] += n
	s.tripped = append(s.tripped, s.enf.Add(Reading{Gen: 1, Core: s.sent})...)
}

// summary is one count read: asked by the kernel, answered by the
// enforcer's count after a fresh reading, through the wire encoding.
func (s *sim) summary() {
	s.t.Helper()
	tk := s.gate.Ask()
	s.enf.Add(Reading{Gen: 1, Core: s.sent})
	b, err := wire.EncodeCounts(s.enf.Counts())
	if err != nil {
		s.t.Fatal(err)
	}
	cs, err := wire.DecodeCounts(b)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := s.gate.Counts(tk, cs); err != nil {
		s.t.Fatal(err)
	}
}

// send is an honest kernel's send of size bytes to dest at addr: reserved
// first, then delivered with retries extra re-sends, then ended. It
// reports the gate's refusal, if any.
func (s *sim) send(dest string, addr netip.Addr, size uint64, retries uint64) error {
	snd, err := s.gate.Reserve(dest, size)
	if err != nil {
		return err
	}
	s.deliver(addr, size*(1+retries))
	snd.End()
	return nil
}

// TestHonestKernelNeverTripsAtTheCapEdges: an honest kernel that sends
// only what capgate admits, retrying each send once, reaches its cap to
// the byte and never trips the enforcer; one byte more is refused as a
// raise, with no trip; counts read at exactly twice wire.SummaryInterval
// still admit a send, and one nanosecond later none does. Destinations
// that share an address are one group, cap the sum. A fake core that
// sends without the gate trips at one byte past the cap (A18: "a send the
// kernel would push past a cap, at each edge ... is refused and asks for a
// raise, with no trip"; "bytes the core sends past a destination's daily
// cap ... are dropped and trip").
func TestHonestKernelNeverTripsAtTheCapEdges(t *testing.T) {
	s := newSim(t, Caps{Core: map[string]uint64{"a.example": 1000, "b.example": 600}})
	s.enf.Resolved("a.example", addrA)
	s.enf.Resolved("b.example", addrA) // one group, cap 1600
	s.summary()

	// Sends that fill the group exactly to its cap, each delivered with
	// its one retry: 2*(400+300+100) = 1600, each destination within its
	// own cap too (capgate also holds those, for a split past midnight).
	if err := s.send("a.example", addrA, 400, 1); err != nil {
		t.Fatalf("a.example 400: %v", err)
	}
	if err := s.send("b.example", addrA, 300, 1); err != nil {
		t.Fatalf("b.example 300: %v", err)
	}
	s.clk.t = s.clk.t.Add(2 * wire.SummaryInterval) // exactly the freshness bound
	if err := s.send("a.example", addrA, 100, 1); err != nil {
		t.Fatalf("at exactly twice the interval, to the cap: %v", err)
	}
	s.summary()
	var past *capgate.PastCap
	if err := s.send("a.example", addrA, 1, 0); !errors.As(err, &past) || past.Raise() == 0 {
		t.Fatalf("one byte past the cap: %v, want a raise", err)
	}
	if len(s.tripped) != 0 {
		t.Fatalf("an honest kernel tripped: %+v", s.tripped)
	}
	if g := groupOf(t, s.enf.Counts(), "a.example"); g.Count != 1600 || g.Cap != 1600 {
		t.Fatalf("group at the cap: %+v", g)
	}

	s.clk.t = s.clk.t.Add(2*wire.SummaryInterval + time.Nanosecond)
	if _, err := s.gate.Reserve("a.example", 0); !errors.Is(err, capgate.ErrNoCount) {
		t.Fatalf("past twice the interval: %v, want no count", err)
	}

	// A fake core that ignores the gate: at the cap nothing trips, one
	// byte past it trips the core.
	s.deliver(addrA, 1)
	if len(s.tripped) == 0 || s.tripped[0].Box != BoxCore || s.tripped[0].Count != 1601 {
		t.Fatalf("one byte past the cap from a fake core: %+v", s.tripped)
	}
}

// TestHonestKernelNeverTripsAcrossAMerge: two destinations with their own
// addresses fill most of their own caps; the enforcer then merges them by
// a shared address mid-day, adding their counts, and the kernel, reading
// the merged group, still stops short of the sum, never tripping.
func TestHonestKernelNeverTripsAcrossAMerge(t *testing.T) {
	s := newSim(t, twoCap) // 100 each
	s.enf.Resolved("a.example", addrA)
	s.enf.Resolved("b.example", addrB)
	s.summary()
	if err := s.send("a.example", addrA, 45, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.send("b.example", addrB, 40, 1); err != nil {
		t.Fatal(err)
	}
	s.enf.Resolved("b.example", addrA) // merged: cap 200, count 170
	s.summary()
	if err := s.send("b.example", addrA, 15, 1); err != nil {
		t.Fatalf("to the merged cap: %v", err)
	}
	if err := s.send("a.example", addrA, 1, 0); !errors.Is(err, capgate.ErrCounting) {
		t.Fatalf("past the merged cap before the ended send is counted: %v, want ErrCounting", err)
	}
	s.summary()
	var past *capgate.PastCap
	if err := s.send("a.example", addrA, 1, 0); !errors.As(err, &past) {
		t.Fatalf("past the merged cap: %v", err)
	}
	if len(s.tripped) != 0 {
		t.Fatalf("an honest kernel tripped across a merge: %+v", s.tripped)
	}
}
