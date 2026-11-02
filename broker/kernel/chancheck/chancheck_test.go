package chancheck

// REQ: NET-2, A18

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

var t0 = time.Unix(1_800_000_000, 0)

func hello(t *testing.T) wire.Hello {
	_, priv, _ := ed25519.GenerateKey(nil)
	h, err := wire.SignHello(wire.RoleCore, priv, bytes.Repeat([]byte{1}, wire.ExporterLen))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// opened is a gate past New's wait, with its connection open, at the time
// it returns.
func opened(t *testing.T) (*Gate, time.Time) {
	t.Helper()
	g := New(t0)
	now := t0.Add(time.Hour)
	_, tk, err := g.Frame(hello(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Answered(tk, now); err != nil {
		t.Fatal(err)
	}
	return g, now.Add(time.Hour)
}

// TestMalformedNeverPasses (NET-2 The channel, A18): every message outside
// the format, or of a type the core does not send, is refused ErrFormat
// with no bytes and no ticket, and takes nothing. Revert mutants: each
// check in encode, and the unknown-kind check.
func TestMalformedNeverPasses(t *testing.T) {
	g, now := opened(t)
	long := strings.Repeat("a", wire.MaxName+1)
	for name, m := range map[string]wire.Msg{
		"nil":                nil,
		"name not a token":   wire.Command{ID: 1, Device: "no such name!", Verb: wire.VerbOn},
		"name too long":      wire.Command{ID: 1, Device: long, Verb: wire.VerbOn},
		"unknown verb":       wire.Command{ID: 1, Device: "lamp", Verb: 99},
		"level on an on":     wire.Command{ID: 1, Device: "lamp", Verb: wire.VerbOn, Level: 3},
		"unknown read":       wire.Read{ID: 1, What: 99},
		"empty entry":        wire.Entry{ID: 1},
		"challenge too long": wire.Challenge{Answer: true, ID: 1, Data: make([]byte, wire.ChallengeData+1)},
		"enforcer's result":  wire.Result{ID: 1, Code: wire.OK},
		"enforcer's alert":   wire.Alert{Text: "x"},
		"device challenge":   wire.Challenge{ID: 1, Data: []byte{1}},
		"read reply":         wire.ReadReply{ID: 1, Body: []byte{1}},
	} {
		b, tk, err := g.Frame(m, now)
		if !errors.Is(err, ErrFormat) || b != nil || tk != (Ticket{}) {
			t.Errorf("%s: %v, %d bytes, ticket %+v; want ErrFormat and nothing", name, err, len(b), tk)
		}
	}
	// Nothing was taken: a full burst still passes.
	l := wire.Rate(wire.RateCommand)
	for i := range l.Burst {
		_, tk, err := g.Frame(wire.Command{ID: uint64(i + 1), Device: "lamp", Verb: wire.VerbOn}, now)
		if err != nil {
			t.Fatalf("command %d: %v", i, err)
		}
		g.Answered(tk, now)
	}
}

// TestBytesAreTheEnforcersFrame: the bytes Frame returns are one frame the
// enforcer's ReadFrame and Decode take whole, of the message passed.
func TestBytesAreTheEnforcersFrame(t *testing.T) {
	g, now := opened(t)
	m := wire.Command{ID: 7, Device: "lamp", Verb: wire.VerbLevel, Level: 40}
	b, _, err := g.Frame(m, now)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(b)
	f, err := wire.ReadFrame(r, wire.ToEnforcer)
	if err != nil || r.Len() != 0 {
		t.Fatalf("read: %v, %d bytes left", err, r.Len())
	}
	back, err := wire.Decode(wire.ToEnforcer, f)
	if err != nil || back != m {
		t.Fatalf("decoded %+v, %v; want %+v", back, err, m)
	}
}

// TestOverRateNeverPasses (A18): with each answer read at once, a kind's
// full burst passes and the next is ErrRate; one slowed interval later one
// more passes, and not before. Revert mutants: the Has check; Answered's
// Spend.
func TestOverRateNeverPasses(t *testing.T) {
	for _, k := range wire.RateKinds[1:] {
		g, now := opened(t)
		l := wire.Rate(k)
		m := func(id uint64) wire.Msg {
			switch k {
			case wire.RateCommand:
				return wire.Command{ID: id, Device: "lamp", Verb: wire.VerbOn}
			case wire.RateTighten:
				return wire.Tighten{ID: id, Kind: wire.CutVendorCloud, Device: "tv"}
			case wire.RateRead:
				return wire.Read{ID: id, What: wire.ReadCounts}
			case wire.RateAnnounce:
				return wire.Announce{ID: id}
			case wire.RateHead:
				return wire.Head{ID: id}
			}
			return wire.Challenge{Answer: true, ID: id, Data: []byte{1}}
		}
		for i := range l.Burst {
			_, tk, err := g.Frame(m(uint64(i+1)), now)
			if err != nil {
				t.Fatalf("kind %d: message %d of the burst: %v", k, i+1, err)
			}
			if err := g.Answered(tk, now); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := g.Frame(m(1000), now); !errors.Is(err, ErrRate) {
			t.Fatalf("kind %d: past the burst: %v, want ErrRate", k, err)
		}
		// The check's clock runs 1/Margin slow, so a refill takes a little
		// longer than Every on the kernel's clock.
		slowed := l.Every + l.Every/(Margin-1) + 1
		if _, _, err := g.Frame(m(1001), now.Add(l.Every)); !errors.Is(err, ErrRate) {
			t.Fatalf("kind %d: one interval on: %v, want ErrRate (Margin)", k, err)
		}
		if _, _, err := g.Frame(m(1002), now.Add(slowed)); err != nil {
			t.Fatalf("kind %d: one slowed interval on: %v", k, err)
		}
	}
}

// TestHeadAndEntryShareARate: a head and an entry take one rate, as the
// enforcer counts them (wire.RateKindOf).
func TestHeadAndEntryShareARate(t *testing.T) {
	g, now := opened(t)
	l := wire.Rate(wire.RateHead)
	for i := range l.Burst {
		var m wire.Msg = wire.Head{ID: uint64(i + 1)}
		if i%2 == 1 {
			m = wire.Entry{ID: uint64(i + 1), Body: []byte{1}}
		}
		_, tk, err := g.Frame(m, now)
		if err != nil {
			t.Fatal(err)
		}
		g.Answered(tk, now)
	}
	if _, _, err := g.Frame(wire.Entry{ID: 9999, Body: []byte{1}}, now); !errors.Is(err, ErrRate) {
		t.Fatalf("an entry after a burst of heads and entries: %v, want ErrRate", err)
	}
}

// TestOneUnansweredPerKind (KRN-chan-1): a second message of a kind waits
// for the first's answer; another kind does not. Revert mutant: the out
// check.
func TestOneUnansweredPerKind(t *testing.T) {
	g, now := opened(t)
	_, tk, err := g.Frame(wire.Announce{ID: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Frame(wire.Announce{ID: 2}, now); !errors.Is(err, ErrWait) {
		t.Fatalf("a second unanswered announce: %v, want ErrWait", err)
	}
	if _, _, err := g.Frame(wire.Head{ID: 3}, now); err != nil {
		t.Fatalf("another kind: %v", err)
	}
	g.Answered(tk, now)
	if _, _, err := g.Frame(wire.Announce{ID: 2}, now); err != nil {
		t.Fatalf("after the answer: %v", err)
	}
}

// TestSpendsAtTheAnswer (KRN-chan-1): a message's token is spent when its
// answer is read, not when it is written, since the enforcer may count it
// as late as that. Revert mutant: spending at Frame's time.
func TestSpendsAtTheAnswer(t *testing.T) {
	g, now := opened(t)
	l := wire.Rate(wire.RateAnnounce)
	for i := range l.Burst - 1 {
		_, tk, _ := g.Frame(wire.Announce{ID: uint64(i + 1)}, now)
		g.Answered(tk, now)
	}
	// The last of the burst is written now and answered after a long
	// delay: the enforcer may have counted it then, when the bucket had
	// refilled, so the bucket is empty again at the answer.
	_, tk, err := g.Frame(wire.Announce{ID: 100}, now)
	if err != nil {
		t.Fatal(err)
	}
	late := now.Add(time.Duration(l.Burst) * l.Every * 2)
	g.Answered(tk, late)
	if _, _, err := g.Frame(wire.Announce{ID: 101}, late); err != nil {
		t.Fatalf("the next after the late answer: %v", err)
	}
	g2, now2 := opened(t)
	_, tk, _ = g2.Frame(wire.Announce{ID: 1}, now2)
	g2.Answered(tk, late)
	// Answered at late: one spent at late, so Burst-1 more pass at late.
	n := 0
	for i := range l.Burst + 1 {
		_, tk, err := g2.Frame(wire.Announce{ID: uint64(10 + i)}, late)
		if err != nil {
			break
		}
		g2.Answered(tk, late)
		n++
	}
	if n != l.Burst-1 {
		t.Fatalf("%d passed after an answer read late, want %d", n, l.Burst-1)
	}
}

// TestConnectionOrder: a hello first and once; nothing else until its
// answer; after Lost, a hello again. Revert mutants: each half of the
// order check, and Lost's closing.
func TestConnectionOrder(t *testing.T) {
	g := New(t0)
	now := t0.Add(time.Hour)
	if _, _, err := g.Frame(wire.Head{ID: 1}, now); !errors.Is(err, ErrOrder) {
		t.Fatalf("a request before the hello: %v, want ErrOrder", err)
	}
	_, tk, err := g.Frame(hello(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Frame(wire.Head{ID: 1}, now); !errors.Is(err, ErrOrder) {
		t.Fatalf("a request before the hello's answer: %v, want ErrOrder", err)
	}
	if _, _, err := g.Frame(hello(t), now); !errors.Is(err, ErrOrder) {
		t.Fatalf("a second hello before the answer: %v, want ErrOrder", err)
	}
	g.Answered(tk, now)
	now = now.Add(time.Hour) // past New's burst
	if _, _, err := g.Frame(hello(t), now); !errors.Is(err, ErrOrder) {
		t.Fatalf("a second hello on an open connection: %v, want ErrOrder", err)
	}
	if _, _, err := g.Frame(wire.Head{ID: 1}, now); err != nil {
		t.Fatalf("a request on the open connection: %v", err)
	}
	g.Lost(now)
	if _, _, err := g.Frame(wire.Head{ID: 2}, now); !errors.Is(err, ErrOrder) {
		t.Fatalf("a request after Lost: %v, want ErrOrder", err)
	}
	if _, _, err := g.Frame(hello(t), now); err != nil {
		t.Fatalf("a hello after Lost: %v", err)
	}
}

// TestTickets: Answered takes only this gate's unanswered ticket, once.
func TestTickets(t *testing.T) {
	g, now := opened(t)
	other, _ := opened(t)
	_, tk, _ := g.Frame(wire.Head{ID: 1}, now)
	_, otk, _ := other.Frame(wire.Head{ID: 1}, now)
	if err := g.Answered(otk, now); !errors.Is(err, ErrTicket) {
		t.Fatalf("another gate's ticket: %v", err)
	}
	if err := g.Answered(Ticket{}, now); !errors.Is(err, ErrTicket) {
		t.Fatalf("the zero ticket: %v", err)
	}
	if err := g.Answered(tk, now); err != nil {
		t.Fatal(err)
	}
	if err := g.Answered(tk, now); !errors.Is(err, ErrTicket) {
		t.Fatalf("a ticket answered twice: %v", err)
	}
	_, tk2, _ := g.Frame(wire.Head{ID: 2}, now)
	g.Lost(now)
	if err := g.Answered(tk2, now); !errors.Is(err, ErrTicket) {
		t.Fatalf("a ticket of a lost connection: %v", err)
	}
}

// TestLostRequestSpentAtNextHello (KRN-chan-2): a request unanswered when
// its connection ends is spent when the next hello is answered, at that
// time. Revert mutants: Lost's pending count; the hello's pending spend.
func TestLostRequestSpentAtNextHello(t *testing.T) {
	g, now := opened(t)
	l := wire.Rate(wire.RateAnnounce)
	for i := range l.Burst - 1 {
		_, tk, _ := g.Frame(wire.Announce{ID: uint64(i + 1)}, now)
		g.Answered(tk, now)
	}
	g.Frame(wire.Announce{ID: 50}, now)
	g.Lost(now)
	later := now.Add(time.Duration(l.Burst) * l.Every * 2)
	_, tk, err := g.Frame(hello(t), later)
	if err != nil {
		t.Fatal(err)
	}
	g.Answered(tk, later)
	n := 0
	for i := range l.Burst + 1 {
		_, tk, err := g.Frame(wire.Announce{ID: uint64(100 + i)}, later)
		if err != nil {
			break
		}
		g.Answered(tk, later)
		n++
	}
	if n != l.Burst-1 {
		t.Fatalf("%d passed after a lost announce, want %d", n, l.Burst-1)
	}
}

// TestNewWaits (KRN-chan-5): a new run assumes the last spent a full
// burst of every kind just before it: the first hello passes one slowed
// interval after New, and each request kind's first one interval after
// that hello's answer. Revert mutants: New's two spends.
func TestNewWaits(t *testing.T) {
	g := New(t0)
	lh := wire.Rate(wire.RateHello)
	slowed := func(d time.Duration) time.Duration { return d + d/(Margin-1) + 1 }
	if _, _, err := g.Frame(hello(t), t0.Add(lh.Every)); !errors.Is(err, ErrRate) {
		t.Fatalf("a hello one interval after New: %v, want ErrRate", err)
	}
	at := t0.Add(slowed(lh.Every))
	_, tk, err := g.Frame(hello(t), at)
	if err != nil {
		t.Fatalf("a hello one slowed interval after New: %v", err)
	}
	g.Answered(tk, at)
	lc := wire.Rate(wire.RateCommand)
	cmd := wire.Command{ID: 1, Device: "lamp", Verb: wire.VerbOn}
	if _, _, err := g.Frame(cmd, at.Add(lc.Every)); !errors.Is(err, ErrRate) {
		t.Fatalf("a command one interval after the first hello: %v, want ErrRate", err)
	}
	if _, _, err := g.Frame(cmd, at.Add(slowed(lc.Every))); err != nil {
		t.Fatalf("a command one slowed interval after the first hello: %v", err)
	}
}

// TestLostHelloSpentLate (KRN-chan-3): a hello unanswered when its
// connection ends is spent at the loss plus MaxLate.
func TestLostHelloSpentLate(t *testing.T) {
	g, now := opened(t)
	g.Lost(now)
	g.Frame(hello(t), now)
	g.Lost(now)
	l := wire.Rate(wire.RateHello)
	// The lost hello is spent at now + MaxLate on the slowed clock, where
	// MaxLate is added whole (it bounds real time, which the slowed clock
	// runs behind): Burst-1 intervals' tolerance less MaxLate's.
	n := 0
	for range l.Burst + 1 {
		_, tk, err := g.Frame(hello(t), now)
		if err != nil {
			break
		}
		g.Answered(tk, now)
		g.Lost(now)
		n++
	}
	want := l.Burst - 1 - int((MaxLate+l.Every-1)/l.Every)
	if n != want {
		t.Fatalf("%d hellos passed after a lost one, want %d", n, want)
	}
}

// TestMaxLateInsideHelloBurst: New's hello spend rests on MaxLate being
// within the hello burst's tolerance (KRN-chan-5).
func TestMaxLateInsideHelloBurst(t *testing.T) {
	l := wire.Rate(wire.RateHello)
	if MaxLate > time.Duration(l.Burst-1)*l.Every {
		t.Fatalf("MaxLate %v is past the hello burst's tolerance", MaxLate)
	}
}

// TestImports: the check links the shared format and the standard
// library only, and no I/O.
func TestImports(t *testing.T) {
	src, err := os.ReadFile("chancheck.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`"os"`, `"net"`, `"io"`, `"os/exec"`} {
		if bytes.Contains(src, []byte(bad)) {
			t.Errorf("chancheck.go imports %s", bad)
		}
	}
}
