package pubid

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: OSS-6

// small takes one slot once signed by the test signer; big takes m.
func small(name string) []byte { return append([]byte(name+":"), make([]byte, 1000)...) }
func big(name string) []byte {
	b := append([]byte(name+":"), make([]byte, MaxPayload)...)
	return b[:MaxPayload]
}

// name recovers an item's name from its signed bytes (the test signer
// prefixes the 32-byte key).
func name(signed []byte) string { n, _, _ := bytes.Cut(signed[32:], []byte(":")); return string(n) }

// OSS-6s-a2: every counted day sends one batch, a signed zero-item cover
// batch under that day's key when nothing is due, so a run of empty days
// between real ones still sends once a day.
func TestOSS6sA2CoverBatchEveryCountedDay(t *testing.T) {
	g := newRig(t, 0)
	before := len(g.out.all)
	if before != 1 {
		t.Fatalf("warm-up sent %d batches, want 1 (its one counted day)", before)
	}
	must(t, g.p.Queue("artifact", small("a")))
	for d := 1; d <= 8; d++ {
		if d == 6 {
			must(t, g.p.Queue("artifact", small("b")))
		}
		g.day(d, 12*time.Hour)
		must(t, g.p.Release())
		must(t, g.p.Release()) // a second tick the same day sends nothing more
		if len(g.out.all) != before+d {
			t.Fatalf("day %d: %d sends, want %d", d, len(g.out.all), before+d)
		}
		s := g.out.all[len(g.out.all)-1]
		priv, _, err := g.id.Key()
		must(t, err)
		if s.day != day(g.c.t) || !s.key.Equal(priv.Public()) {
			t.Fatalf("day %d: batch for %s", d, s.day)
		}
		want := 0
		if d == 1 || d == 6 {
			want = 1
		}
		if len(s.batch) != want {
			t.Fatalf("day %d: %d items, want %d", d, len(s.batch), want)
		}
	}
}

// OSS-6s-a3 Selection, test 1 (P4): on an overflow day, which items of a
// cohort carry does not depend on the order they were queued in.
func TestOSS6sA3CarryIgnoresQueueOrder(t *testing.T) {
	g := newRig(t, 0)
	other := &fakeSender{}
	q, err := NewPublisher(Config{Path: filepath.Join(g.dir, "o2.json"), Identity: g.id, Sender: other, Now: g.c.now,
		Signers: map[string]Signer{"artifact": signer}, Rand: g.rand, Mono: g.mono})
	must(t, err)
	g.warm(t, q)
	n := UsableSlots + 5
	for i := range n {
		must(t, g.p.Queue("artifact", small(fmt.Sprint(i))))
		must(t, q.Queue("artifact", small(fmt.Sprint(n-1-i))))
	}
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	must(t, q.Release())
	a, b := g.out.all[len(g.out.all)-1], other.all[len(other.all)-1]
	if len(a.batch) != UsableSlots || !bytes.Equal(a.raw, b.raw) {
		t.Fatalf("%d items; the two queue orders published different batches", len(a.batch))
	}
	if g.p.Len() != 5 || q.Len() != 5 {
		t.Fatalf("carried %d and %d", g.p.Len(), q.Len())
	}
	g.day(2, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.all[len(g.out.all)-1].batch) != 5 || g.p.Len() != 0 {
		t.Fatal("the carried items did not leave the next counted day")
	}
}

// OSS-6s-a3 Selection, test 2 (bounded wait): under constant overload
// every item is published within N = ceil(B/(C−m+1)) counted days of its
// due day, carried cohorts go before younger ones, and an adversarial
// cohort order (each cohort's 1-slot items ahead of its m-slot items)
// does not break the bound.
func TestOSS6sA3BoundedWaitUnderOverload(t *testing.T) {
	adversarial := func(_ []byte, _ string, it item) []byte {
		if len(it.Payload) == MaxPayload {
			return []byte{1}
		}
		return []byte{0}
	}
	for _, order := range []struct {
		name string
		rank func([]byte, string, item) []byte
	}{{"keyed", cohortRank}, {"adversarial", adversarial}} {
		t.Run(order.name, func(t *testing.T) {
			saved := cohortRank
			cohortRank = order.rank
			t.Cleanup(func() { cohortRank = saved })
			boundedWait(t)
		})
	}
}

func boundedWait(t *testing.T) {
	g := newRig(t, 0)
	r := rand.New(rand.NewPCG(1, 2))
	slotsOf := func(it item) int { return ItemSlots(len(it.Payload) + 32) }
	type track struct{ due, bound int64 }
	waiting := map[string]*track{}
	divisor := UsableSlots - MaxItemSlots + 1
	worst, seq := 0, 0
	for d := 1; d <= 40 || g.p.Len() > 0 && d <= 400; d++ {
		g.day(d, 12*time.Hour)
		count := g.p.st.Count + 1
		b := 0
		for _, it := range g.p.st.Items {
			if it.Wait <= 1 {
				b += slotsOf(it)
			}
		}
		for _, it := range g.p.st.Items {
			if it.Wait == 1 {
				waiting[name(append(make([]byte, 32), it.Payload...))] = &track{count, int64((b + divisor - 1) / divisor)}
			}
		}
		must(t, g.p.Release())
		var maxDue int64
		for _, raw := range g.out.all[len(g.out.all)-1].batch {
			tr := waiting[name(raw)]
			if tr == nil {
				t.Fatalf("day %d: %s published twice or unknown", d, name(raw))
			}
			if took := count - tr.due + 1; took > tr.bound {
				t.Fatalf("day %d: %s took %d counted days, bound %d", d, name(raw), took, tr.bound)
			} else if int(took) > worst {
				worst = int(took)
			}
			maxDue = max(maxDue, tr.due)
			delete(waiting, name(raw))
		}
		for _, it := range g.p.st.Items {
			if it.Wait == 0 && it.Due < maxDue {
				t.Fatalf("day %d: an item due on %d carried while one due on %d left", d, it.Due, maxDue)
			}
		}
		// Overload: about 1.5×C slots arrive a day until day 30, then the
		// queue drains.
		for arrived := 0; d <= 30 && arrived < UsableSlots*3/2; seq++ {
			p := small(fmt.Sprint(seq))
			if r.IntN(4) == 0 {
				p = big(fmt.Sprint(seq))
			}
			if err := g.p.Queue("artifact", p); err != nil {
				break // ErrFull
			}
			arrived += ItemSlots(len(p) + 32)
		}
	}
	if len(waiting) != 0 || g.p.Len() != 0 {
		t.Fatalf("%d items never left", len(waiting))
	}
	t.Logf("worst wait %d counted days", worst)
	if worst < 2 {
		t.Fatalf("the overload never carried an item (worst %d)", worst)
	}
}

// OSS-6s-a3 Storage: a carried item is stored with Wait 0 and its due
// day, loads after a restart, and leaves on the next counted day; the
// loader refuses a carried item due after the current counted day or older
// than the queue bound allows.
func TestOSS6sA3CarriedItemSurvivesARestart(t *testing.T) {
	g := newRig(t, 0)
	for i := range UsableSlots + 1 {
		must(t, g.p.Queue("artifact", small(fmt.Sprint(i))))
	}
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	if g.p.Len() != 1 || g.p.st.Items[0].Wait != 0 || g.p.st.Items[0].Due != g.p.st.Count {
		t.Fatalf("carried %+v at count %d", g.p.st.Items, g.p.st.Count)
	}
	g.reopen(t)
	if g.p.Len() != 1 {
		t.Fatal("the carried item did not load")
	}
	g.day(2, 12*time.Hour)
	must(t, g.p.Release())
	if s := g.out.all[len(g.out.all)-1]; len(s.batch) != 1 || g.p.Len() != 0 {
		t.Fatalf("the carried item did not leave: %d items, %d left", len(s.batch), g.p.Len())
	}

	path := filepath.Join(g.dir, "o3.json")
	carried := func(due, count int64) string {
		return fmt.Sprintf(`{"items":[{"kind":"artifact","payload":"eA==","wait":0,"due":%d}],"count":%d}`, due, count)
	}
	open := func(body string) error {
		must(t, os.WriteFile(path, []byte(body), 0o600))
		_, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Signers: map[string]Signer{"artifact": signer}})
		return err
	}
	age := int64(MaxQueue * MaxItemSlots)
	if err := open(carried(5, 5+age)); err != nil {
		t.Fatalf("a carried item at the age bound: %v", err)
	}
	for name, body := range map[string]string{
		"due ahead":    carried(6, 5),
		"too old":      carried(5, 6+age),
		"no due":       carried(0, 5),
		"due, waiting": strings.Replace(carried(5, 5), `"wait":0`, `"wait":1`, 1),
		"bad count":    carried(5, -1),
	} {
		if err := open(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// OSS-6s-a3: overflow only lengthens waits; the clock model's floor still
// holds for carried items (G1), and Clear discards them.
func TestOSS6sA3ClearDiscardsCarriedItems(t *testing.T) {
	g := newRig(t, 0)
	for i := range UsableSlots + 3 {
		must(t, g.p.Queue("artifact", small(fmt.Sprint(i))))
	}
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	if n, err := g.p.Clear(); err != nil || n != 3 {
		t.Fatalf("cleared %d: %v", n, err)
	}
	g.day(2, 12*time.Hour)
	must(t, g.p.Release())
	if s := g.out.all[len(g.out.all)-1]; len(s.batch) != 0 {
		t.Fatal("a cleared item left")
	}
}
