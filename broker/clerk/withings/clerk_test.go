package withings

// REQ: CLK-1, STO-2, DEV-3, DEV-8, PLN-3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
)

// sealedKeeper is a Keeper over a real sealed store holding the canary kl,
// opened through clerk.Secrets.DeviceKey as part b wires it.
func sealedKeeper(t *testing.T, mac string) (*Keeper, *clerk.Secrets) {
	t.Helper()
	sl, err := clerk.NewAESSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := clerk.NewSecrets(sl, nil)
	if err := s.Put("device/withings", clerk.KindStatic, []byte(klCanary)); err != nil {
		t.Fatal(err)
	}
	return &Keeper{Open: s.DeviceKey("device/withings"), MAC: mac}, s
}

type bus struct{ got []Event }

func (b *bus) emit(e Event) error { b.got = append(b.got, e); return nil }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newClerk(t *testing.T, logs *[]string) (*Clerk, *bus, *clock) {
	k, _ := sealedKeeper(t, "aa:bb:cc:dd:ee:ff")
	b, c := &bus{}, &clock{time.Unix(1800000000, 0)}
	return &Clerk{Keeper: k, Owner: map[uint32]bool{7: true}, Emit: b.emit, Now: c.now,
		Log: func(s string) { *logs = append(*logs, s) }}, b, c
}

func readOnce(t *testing.T, c *Clerk, f *fakeScale) (int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.Read(ctx, f)
}

// A read through the sealed store puts each owner reading on the bus as one
// event, private and unverified, with no scale text; another household
// member's weigh-in and slot 0 never leave; a reading already sent is not
// sent again when the scale resends its store.
func TestClerkPutsOwnerReadingsOnTheBusPrivateAndUnverified(t *testing.T) {
	var logs []string
	c, b, clk := newClerk(t, &logs)
	f := newScale()
	twoWeighIns(f) // slot 7: three readings; slot 8: one
	f.records = append(f.records, []tlv{meta(1700007200, 1, 0), data(5000, 1, -2)})
	n, err := readOnce(t, c, f)
	if err != nil || n != 3 || len(b.got) != 3 {
		t.Fatalf("sent %d (%d events), %v", n, len(b.got), err)
	}
	for _, e := range b.got {
		if e.Label != Label || Label != "private" || !e.Unverified || !e.Reading.Unverified ||
			e.Reading.User != 7 || e.Device != Declaration.Device {
			t.Fatalf("event %+v", e)
		}
		if s := fmt.Sprintf("%+v", e); strings.Contains(s, "Body Smart") || strings.Contains(s, "MFG") || strings.Contains(s, f.mac) {
			t.Fatalf("event carries scale text: %s", s)
		}
	}
	if st := c.Stats(); st.Others != 2 {
		t.Fatalf("stats %+v", st)
	}
	clk.t = clk.t.Add(DefaultGap)
	f2 := newScale()
	twoWeighIns(f2)
	f2.records = append(f2.records, []tlv{meta(1700090000, 1, 7), data(8100, 1, -2)})
	if n, err := readOnce(t, c, f2); err != nil || n != 1 || b.got[3].Reading.Time != 1700090000 {
		t.Fatalf("second read sent %d, %v", n, err)
	}
	if m := c.MarksCopy(); m[7] != 1700090000 || len(m) != 1 {
		t.Fatalf("marks %v", m)
	}
}

// A flood of reads is coalesced: within the gap, a read does not connect
// and is counted.
func TestClerkCoalescesAFloodOfReads(t *testing.T) {
	var logs []string
	c, b, clk := newClerk(t, &logs)
	f := newScale()
	twoWeighIns(f)
	if _, err := readOnce(t, c, f); err != nil {
		t.Fatal(err)
	}
	before := len(f.frames())
	for i := 0; i < 100; i++ {
		clk.t = clk.t.Add(time.Second / 2)
		if n, err := readOnce(t, c, f); n != 0 || err != nil {
			t.Fatalf("read %d sent %d, %v", i, n, err)
		}
	}
	if len(f.frames()) != before || len(b.got) != 3 {
		t.Fatalf("a coalesced read connected: %d frames, %d events", len(f.frames())-before, len(b.got))
	}
	if st := c.Stats(); st.Coalesced != 100 {
		t.Fatalf("stats %+v", st)
	}
}

// weighIn is one weigh-in at time t by slot 7 with the first n measures.
func weighIn(t uint32, n int) []tlv {
	codes := []uint16{1, 5, 6, 8, 11, 76, 77, 88, 170, 226, 227}
	r := []tlv{meta(t, 1, 7)}
	for _, c := range codes[:n] {
		r = append(r, data(1, c, 0))
	}
	return r
}

// Past MaxEvents, whole weigh-ins wait for the next read, oldest first, and
// none is lost: a weigh-in that exactly fills the limit goes, one that
// overflows it by one waits. A limit below one weigh-in's size is raised to
// it, so the clerk never stalls.
func TestClerkDefersWholeWeighInsPastTheLimit(t *testing.T) {
	for _, c := range []struct {
		name        string
		max         int
		sizes       []int
		first, rest int
	}{
		{"exact fill", len(measures), []int{6, 5, 1}, 11, 1},
		{"over by one", len(measures), []int{6, 6}, 6, 6},
		{"limit below a weigh-in", 2, []int{11, 1}, 11, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			var logs []string
			cl, b, clk := newClerk(t, &logs)
			cl.MaxEvents = c.max
			f := newScale()
			for i, n := range c.sizes {
				f.records = append(f.records, weighIn(uint32(100*(i+1)), n))
			}
			if n, err := readOnce(t, cl, f); err != nil || n != c.first {
				t.Fatalf("first read sent %d, %v; want %d", n, err, c.first)
			}
			if st := cl.Stats(); st.Deferred != c.rest {
				t.Fatalf("stats %+v", st)
			}
			clk.t = clk.t.Add(DefaultGap)
			if n, _ := readOnce(t, cl, f); n != c.rest || len(b.got) != c.first+c.rest {
				t.Fatalf("second read sent %d", n)
			}
			for i := 1; i < len(b.got); i++ {
				if b.got[i].Reading.Time < b.got[i-1].Reading.Time {
					t.Fatal("weigh-ins out of order")
				}
			}
		})
	}
}

// Slot 0 (the scale did not know whose weigh-in it was) never leaves, even
// when a host lists it as the owner's.
func TestClerkNeverEmitsSlotZero(t *testing.T) {
	var logs []string
	c, b, _ := newClerk(t, &logs)
	c.Owner[0] = true
	f := newScale()
	f.records = [][]tlv{{meta(1700007200, 1, 0), data(5000, 1, -2)}}
	if _, err := readOnce(t, c, f); err != nil {
		t.Fatal(err)
	}
	if len(b.got) != 0 || c.Stats().Others != 1 {
		t.Fatalf("slot 0 on the bus: %+v, stats %+v", b.got, c.Stats())
	}
}

// A weigh-in at or below its slot's mark (a scale clock set back) is
// counted, not dropped silently; a failed read is counted too.
func TestClerkCountsStaleAndFailedReads(t *testing.T) {
	var logs []string
	c, _, clk := newClerk(t, &logs)
	c.Marks = map[uint32]int64{7: 1700000000}
	f := newScale()
	twoWeighIns(f)
	if n, err := readOnce(t, c, f); err != nil || n != 0 {
		t.Fatalf("sent %d, %v", n, err)
	}
	clk.t = clk.t.Add(DefaultGap)
	bad := newScale()
	bad.badProof = true
	_, _ = readOnce(t, c, bad)
	if st := c.Stats(); st.Stale != 3 || st.Failed != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// A bus that refuses an event leaves the weigh-in's mark unmoved, so it is
// offered again.
func TestClerkRetriesAWeighInTheBusRefused(t *testing.T) {
	var logs []string
	c, b, clk := newClerk(t, &logs)
	fail := true
	c.Emit = func(e Event) error {
		if fail {
			return errors.New("bus full")
		}
		return b.emit(e)
	}
	f := newScale()
	twoWeighIns(f)
	if _, err := readOnce(t, c, f); err == nil {
		t.Fatal("a refused event read as sent")
	}
	fail = false
	clk.t = clk.t.Add(DefaultGap)
	if n, err := readOnce(t, c, f); err != nil || n != 3 {
		t.Fatalf("retry sent %d, %v", n, err)
	}
}

// kl is read only inside the Keeper: the canary is in no log line, error,
// event, written frame or printed value of the clerk.
func TestClerkKlNeverLeaves(t *testing.T) {
	var logs []string
	c, b, clk := newClerk(t, &logs)
	f := newScale()
	twoWeighIns(f)
	_, err1 := readOnce(t, c, f)
	clk.t = clk.t.Add(DefaultGap)
	bad := newScale()
	bad.badProof = true
	_, err2 := readOnce(t, c, bad)
	var all []string
	all = append(all, logs...)
	all = append(all, fmt.Sprint(err1), fmt.Sprint(err2), fmt.Sprintf("%v %+v %#v %v", c, c, c.Keeper, b.got))
	for _, w := range append(f.frames(), bad.frames()...) {
		all = append(all, string(w))
	}
	for _, s := range all {
		if strings.Contains(s, klCanary) {
			t.Fatalf("kl leaked: %q", s)
		}
	}
	if !errors.Is(err2, ErrUnproven) {
		t.Fatalf("unproven scale read as %v", err2)
	}
}

// The prover answers only for the paired scale's MAC.
func TestKeeperAnswersOnlyThePairedScale(t *testing.T) {
	k, _ := sealedKeeper(t, "aa:bb:cc:dd:ee:ff")
	p, _ := k.Prove(context.Background())
	defer p.Close()
	if _, err := p.Answer(scaleChallenge, "11:22:33:44:55:66"); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("answered another scale: %v", err)
	}
	var logs []string
	c, _, _ := newClerk(t, &logs)
	c.Keeper.MAC = "11:22:33:44:55:66"
	f := newScale()
	if _, err := readOnce(t, c, f); !errors.Is(err, ErrUnproven) {
		t.Fatalf("read of an unpaired scale: %v", err)
	}
	for _, w := range f.frames()[1:] {
		if m, _ := decode(w); m.cmd != cmdDisconnect {
			t.Fatalf("unpaired scale got command %d", m.cmd)
		}
	}
}

// The prover is no reflection oracle: one session at a time, one answer and
// one check per session in that order, and never an answer to a challenge
// we sent ourselves.
func TestKeeperIsNoReflectionOracle(t *testing.T) {
	k, _ := sealedKeeper(t, "aa:bb:cc:dd:ee:ff")
	mac := k.MAC
	p, err := k.Prove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A second session waits for the first.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if _, err := k.Prove(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("two sessions at once: %v", err)
	}
	cancel()
	own := bytes.Repeat([]byte{0xa5}, 16)
	if p.Check(own, mac, sha(own, []byte(mac), []byte(klCanary))) {
		t.Fatal("checked before answering")
	}
	if _, err := p.Answer(scaleChallenge, mac); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Answer(own, mac); !errors.Is(err, ErrProofUsed) {
		t.Fatalf("second answer: %v", err)
	}
	if p.Check(scaleChallenge, mac, sha(scaleChallenge, []byte(mac), []byte(klCanary))) {
		t.Fatal("checked the scale's own challenge as ours")
	}
	p.Close()
	p.Close()
	p2, _ := k.Prove(context.Background())
	_, _ = p2.Answer(scaleChallenge, mac)
	if !p2.Check(own, mac, sha(own, []byte(mac), []byte(klCanary))) {
		t.Fatal("a good answer failed the check")
	}
	if p2.Check(own, mac, sha(own, []byte(mac), []byte(klCanary))) {
		t.Fatal("checked twice")
	}
	p2.Close()
	// A closed proof neither answers nor checks.
	if _, err := (&Proof{k: k, closed: true}).Answer(scaleChallenge, mac); !errors.Is(err, ErrProofUsed) {
		t.Fatalf("closed proof answered: %v", err)
	}
	p4 := &Proof{k: k, answered: scaleChallenge, closed: true}
	if p4.Check(own, mac, sha(own, []byte(mac), []byte(klCanary))) {
		t.Fatal("closed proof checked")
	}
	// A later session's peer offers our earlier challenge: not answered.
	p3, _ := k.Prove(context.Background())
	defer p3.Close()
	if _, err := p3.Answer(own, mac); !errors.Is(err, ErrReflected) {
		t.Fatalf("answered our own challenge: %v", err)
	}
}
