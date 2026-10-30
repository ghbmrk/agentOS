package sim

// REQ: KRN-6, KRN-12

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/decoy"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// tripRun drives a kernel from seed through a decoy table and a mix of clean
// plans and plans that trip in every way, with call trips and passkey
// resumes, and returns the log.
func tripRun(t *testing.T, seed uint64) ([]kernel.Entry, []key.PublicKey, *kernel.Kernel) {
	t.Helper()
	rng := rand.New(rand.NewPCG(seed, seed^0x5eed))
	kp := func() ed25519.PrivateKey {
		var s [ed25519.SeedSize]byte
		for i := range s {
			s[i] = byte(rng.UintN(256))
		}
		return ed25519.NewKeyFromSeed(s[:])
	}
	owner, spare, holder, head := kp(), kp(), kp(), kp()
	anchors := []key.PublicKey{key.Ed25519(owner.Public().(ed25519.PublicKey)), key.Ed25519(spare.Public().(ed25519.PublicKey))}
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{},
		Pub: head.Public().(ed25519.PublicKey), Sign: head, Rand: rand.NewChaCha8([32]byte{byte(seed)})})
	if err != nil {
		t.Fatal(err)
	}
	var clock int64
	mail := (&world{anchors: anchors, now: &clock}).newMail()
	mail.Fault = nil
	k, err := kernel.Boot(l, anchors, map[string]kernel.Clerk{"mail": mail}, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := key.Issue(key.Ed25519Signer(owner), key.Root{Clerk: "mail", Verbs: []key.Verb{key.Organize, key.Trash, key.Send}, Serial: "s"})
	ck, err := key.ClerkKey(root, key.Ed25519Signer(owner), holder.Public().(ed25519.PublicKey), 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	keys := []key.Key{root, ck}
	h := kernel.BatchHash(keys...)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(k.Issue(-kernel.GrantHold, []key.Cosign{key.Approve(key.Ed25519Signer(owner), h), key.Approve(key.Ed25519Signer(spare), h)}, keys...))

	tb, err := decoy.Generate(rand.NewChaCha8([32]byte{byte(seed), 1}), []netip.Addr{netip.MustParseAddr("10.9.8.7")}, kernel.HoneyKeys)
	must(err)
	must(k.LogDecoyTable(1, tb))
	es := tb.Entries()
	now := int64(10)
	for i := 0; i < 60; i++ {
		now += int64(rng.IntN(5000))
		task := fmt.Sprintf("t%d", i)
		if err := k.OpenTask(now, task); err != nil && !k.State().Tripped() {
			t.Fatal(err) // refused only while a full trip stops planning
		}
		ky, err := key.Derive(ck, holder, holder.Public().(ed25519.PublicKey), key.LimitTask(task))
		must(err)
		if rng.IntN(3) == 0 {
			ky = ck // no planner session
		}
		arg := fmt.Sprintf("m%d", i)
		switch rng.IntN(5) {
		case 0:
			arg = es[rng.IntN(len(es))].Value
		case 1:
			arg = "http://" + es[rng.IntN(len(es))].Dest.String() + "/"
		case 2:
			var hk key.Key
			for _, e := range es {
				if e.Kind == decoy.KHoneyKey {
					must(json.Unmarshal([]byte(e.Value), &hk))
				}
			}
			ky = hk
		}
		p := kernel.SignPlan(kernel.Plan{ID: fmt.Sprintf("p%d", i), Key: ky,
			Steps: []kernel.PlanStep{{Verb: key.Trash, Clerk: "mail", Args: map[string]string{"message": arg}}}}, holder)
		must(k.Submit(now, p))
		if rng.IntN(6) == 0 {
			must(k.CallTrip(now, kernel.ExitEgress, es[rng.IntN(len(es))].Dest))
		}
		if n, last, ok := k.State().TripResume(); ok && rng.IntN(2) == 0 {
			must(k.ResumeTrip(now, key.Approve(key.Ed25519Signer(owner), kernel.TripResumeHash(n, last))))
		}
		clock = now
		must(k.Tick(now))
	}
	return l.Entries(), anchors, k
}

// The same log and events give the same trip entries: a run is byte for
// byte the same from its seed, a replay folds the same trips, and every trip
// a plan gave is derived again from the entries before it (KRN-6). Catches a
// nondeterministic matcher in the kernel.
func TestTripDeterministic(t *testing.T) {
	for seed := uint64(1); seed <= 8; seed++ {
		es, anchors, k := tripRun(t, seed)
		again, _, _ := tripRun(t, seed)
		if !reflect.DeepEqual(es, again) {
			t.Fatalf("seed %d: two runs logged different entries", seed)
		}
		re, err := kernel.Replay(anchors, es)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(re.Trips(), k.State().Trips()) || len(re.Trips()) == 0 {
			t.Fatalf("seed %d: replay folds %d trips, live %d", seed, len(re.Trips()), len(k.State().Trips()))
		}
		got, err := kernel.Rederive(anchors, k.Box(), es)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if got.Checked[kernel.TTrip] == 0 {
			t.Fatalf("seed %d: no plan trip re-derived: %v", seed, got.Checked)
		}

		// A plan's trip logged with another response is a divergence.
		for i, e := range es {
			if e.Type != kernel.TTrip || !bytes.Contains(e.Body, []byte(`"plan"`)) {
				continue
			}
			bad := append([]kernel.Entry(nil), es...)
			bad[i].Body = bytes.Replace(e.Body, []byte(`"response":"`), []byte(`"response":"x`), 1)
			var d *kernel.Divergence
			if _, err := kernel.Rederive(anchors, k.Box(), bad); !errors.As(err, &d) || d.Seq != e.Seq {
				t.Fatalf("seed %d: an altered trip at %d gave %v", seed, e.Seq, err)
			}
			break
		}
	}
}
