package proc

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// unstamped is a Source's reading without its Stamp.
func unstamped(r kernel.Reading, _ Stamp) kernel.Reading { return r }

// stamped is a Source reading *r on the sample *at (zero: none).
func stamped(r *kernel.Reading, at *byte) Source {
	return func() (kernel.Reading, Stamp) { return *r, Stamp{11: *at} }
}

// Once a source has a fresh sample, Earliest rises to that sample's bound
// and runs on from there: a kernel started behind true time (a flat CMOS
// battery, the log's last time) catches up when chronyd syncs, so a hold
// waits its length, not the gap (#5759). A sample is fresh when its Stamp
// differs from the last one seen, earlier or later (chronyd fuzzes each by
// up to a second); the zero Stamp vouches for none, and a fresh sample below
// Earliest lowers nothing.
//
// REQ: TIM-1, KEY-7, KEY-8
func TestTIM1AFreshSampleRaisesEarliest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: pub, Sign: priv, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	const last = int64(1_000_000_000_000)
	if _, err := l.Append(last, kernel.TStop, 1, struct{}{}); err != nil {
		t.Fatal(err)
	}
	gap := 30 * key.DayMS
	src, at := kernel.Reading{Latest: 1}, byte(0) // the box restarted at 1970, chronyd not yet synced
	w := onLog(l, stamped(&src, &at))
	if r := w(); r.Earliest < last || r.Earliest >= last+key.DayMS {
		t.Fatalf("the start read %+v, not the log's %d", r, last)
	}
	// chronyd syncs: true time is the gap past the log. Earliest rises to
	// the sample's bound and runs on from that read, not from the start.
	time.Sleep(50 * time.Millisecond)
	src, at = kernel.Reading{Earliest: last + gap, Latest: last + gap + 10}, 7
	if r := w(); r.Earliest != last+gap || r.Latest != last+gap+10 {
		t.Fatalf("a first sample read %+v: want Earliest raised to %d", r, last+gap)
	}
	risen := time.Now()
	if r := w(); r.Earliest > last+gap+time.Since(risen).Milliseconds()+1 {
		t.Fatalf("after the rise read %+v: Earliest ran on from the start, not the rise", r)
	}
	// The same sample, then the zero Stamp, following small box steps: no rise.
	for _, a := range []byte{7, 0} {
		at = a
		src = kernel.Reading{Earliest: last + gap + 9_000, Latest: last + gap + 9_010}
		if r := w(); r.Earliest >= last+gap+9_000 {
			t.Fatalf("stamp %d read %+v: a reading on no new sample raised Earliest", a, r)
		}
	}
	// A new sample, with a stamp below the last (the fuzz), raises it again;
	// one below Earliest lowers nothing, and Earliest runs on from the rise.
	src, at = kernel.Reading{Earliest: last + 2*gap, Latest: last + 2*gap}, 3
	if r := w(); r.Earliest != last+2*gap {
		t.Fatalf("a second sample read %+v: want Earliest raised to %d", r, last+2*gap)
	}
	src, at = kernel.Reading{Earliest: last, Latest: last}, 4
	if r := w(); r.Earliest < last+2*gap || r.Latest != r.Earliest {
		t.Fatalf("a sample behind Earliest read %+v: Earliest went back", r)
	}
	for r := w(); r.Earliest == last+2*gap; r = w() { // a stopped time spins to the test's timeout
	}
}

// onLog's clock is read from more than one goroutine (a re-seal reads it off
// the kernel's lock), so it takes and applies each reading under one lock:
// the source is never read by two at once, so no reading on an older sample
// is applied after a fresher one, which would make the fresher sample count
// as fresh again (#6304 L3 1, Security 1). Earliest never goes back.
//
// REQ: TIM-1
func TestTIM1AOnLogReadsAndAppliesUnderOneLock(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: pub, Sign: priv, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	var n, in atomic.Int64
	var overlap atomic.Bool
	w := onLog(l, func() (kernel.Reading, Stamp) {
		if in.Add(1) > 1 {
			overlap.Store(true)
		}
		defer in.Add(-1)
		time.Sleep(100 * time.Microsecond) // a chronyd round trip
		i := n.Add(1)
		return kernel.At(i * 1000), Stamp{0: byte(i), 1: byte(i >> 8)}
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			prev := int64(0)
			for range 50 {
				r := w()
				if r.Earliest < prev {
					t.Errorf("Earliest went back: %d after %d", r.Earliest, prev)
					return
				}
				prev = r.Earliest
			}
		}()
	}
	wg.Wait()
	if overlap.Load() {
		t.Fatal("two readers read the source at once: a stale reading can be applied after a fresh one")
	}
}
