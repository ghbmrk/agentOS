package wire

import (
	"math/rand/v2"
	"testing"
	"time"
)

// REQ: NET-2

// TestEveryCoreTypeHasARate: each type the core sends has a kind with a
// positive rate, a head and an entry share one, and nothing the enforcer
// sends has one. Revert mutant: any case of RateKindOf or Rate.
func TestEveryCoreTypeHasARate(t *testing.T) {
	seen := map[RateKind]bool{}
	for typ := range types[ToEnforcer] {
		k := RateKindOf(typ)
		if k == 0 {
			t.Errorf("type %d from the core has no rate", typ)
		}
		if l := Rate(k); l.Burst < 2 || l.Every <= 0 {
			t.Errorf("type %d: rate %+v", typ, l)
		}
		seen[k] = true
	}
	if len(seen) != len(RateKinds) {
		t.Errorf("%d kinds reached from the core's types, %d listed", len(seen), len(RateKinds))
	}
	if RateKindOf(THead) != RateHead || RateKindOf(TEntry) != RateHead {
		t.Error("a head and an entry do not share a rate")
	}
	for typ := range types[ToCore] {
		if typ != THello && RateKindOf(typ) != 0 {
			t.Errorf("enforcer type %d has a rate", typ)
		}
	}
	want := map[Type]RateKind{THello: RateHello, TCommand: RateCommand, TTighten: RateTighten, TRead: RateRead,
		TAnnounce: RateAnnounce, THead: RateHead, TEntry: RateHead, TAnswer: RateAnswer}
	for typ, k := range want {
		if RateKindOf(typ) != k {
			t.Errorf("type %d counts as %d, want %d", typ, RateKindOf(typ), k)
		}
	}
	if (Rate(0) != Limit{}) {
		t.Error("an unlisted kind has a rate")
	}
	if NewBucket(Rate(0), time.Unix(0, 0)).Has(time.Unix(0, 0)) {
		t.Error("the zero Limit admits a message")
	}
}

// TestRateNumbers pins the table both ends read (ENF-d-w7).
func TestRateNumbers(t *testing.T) {
	want := map[RateKind]Limit{
		RateHello: {10, time.Minute}, RateCommand: {30, 2 * time.Second}, RateTighten: {20, time.Minute},
		RateRead: {120, 250 * time.Millisecond}, RateAnnounce: {5, 10 * time.Minute},
		RateHead: {600, 100 * time.Millisecond}, RateAnswer: {30, 2 * time.Second},
	}
	for k, l := range want {
		if Rate(k) != l {
			t.Errorf("kind %d: %+v, want %+v", k, Rate(k), l)
		}
	}
}

// TestBucketEdges: a full bucket gives Burst at once and then one each
// Every, exactly at the interval and not a nanosecond before; a full
// bucket banks no time; a clock stepped back refills nothing. Revert
// mutants: each comparison in Has, Take and see.
func TestBucketEdges(t *testing.T) {
	l := Limit{Burst: 3, Every: time.Second}
	at := time.Unix(1000, 0)
	b := NewBucket(l, at)
	for i := range 3 {
		if !b.Take(at) {
			t.Fatalf("token %d of the burst", i)
		}
	}
	if b.Has(at) || b.Take(at) {
		t.Fatal("a token past the burst")
	}
	if b.Has(at.Add(time.Second - 1)) {
		t.Fatal("a token a nanosecond before the interval")
	}
	if !b.Take(at.Add(time.Second)) {
		t.Fatal("no token at the interval")
	}
	if b.Has(at) {
		t.Fatal("a clock stepped back refilled the bucket")
	}
	// Idle long past full: still only Burst at once.
	later := at.Add(time.Hour)
	n := 0
	for b.Take(later) {
		n++
	}
	if n != 3 {
		t.Fatalf("%d tokens after an idle hour, want 3", n)
	}
	// Spend counts without a token, and moves no clock.
	b2 := NewBucket(l, at)
	for range 5 {
		b2.Spend(at)
	}
	if b2.Has(at.Add(2 * time.Second)) {
		t.Fatal("five spent at once leave a token two intervals on")
	}
	if !b2.Has(at.Add(3 * time.Second)) {
		t.Fatal("five spent at once leave no token three intervals on")
	}
	b3 := NewBucket(l, at)
	b3.Spend(at.Add(time.Hour))
	if b3.Has(at.Add(time.Hour - 2*time.Second)) {
		t.Fatal("a spend in the future moved the bucket's clock")
	}
}

// TestBucketLaterIsSafer: the two facts the kernel's check rests on
// (ENF-d-w7). Over random arrivals, a bucket that counts every message no
// earlier than another bucket counted it, and checks each no later, never
// passes a message the other refuses. Revert mutant: Spend not taking the
// later of full and the arrival.
func TestBucketLaterIsSafer(t *testing.T) {
	rng := rand.New(rand.NewPCG(4373, 7))
	l := Limit{Burst: 4, Every: time.Second}
	for run := range 2000 {
		at := time.Unix(0, 0)
		early := NewBucket(l, at) // the enforcer: counts at the arrival
		late := NewBucket(l, at)  // the kernel: checks at the send, spends at the answer
		now := at
		for range 50 {
			now = now.Add(time.Duration(rng.Int64N(int64(1500 * time.Millisecond))))
			if !late.Has(now) {
				continue
			}
			arrive := now.Add(time.Duration(rng.Int64N(int64(2 * time.Second))))
			answer := arrive.Add(time.Duration(rng.Int64N(int64(time.Second))))
			if !early.Take(arrive) {
				t.Fatalf("run %d: the enforcer's bucket refused a message the late bucket passed", run)
			}
			late.Spend(answer)
			now = answer
		}
	}
}
