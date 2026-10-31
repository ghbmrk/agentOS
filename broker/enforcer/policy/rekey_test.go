package policy

// REQ: NET-4, STO-4, NET-2

import (
	"errors"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// TestRekeyKeepsPolicyUnderNewPasskey: a new passkey takes the policy in
// force only by signing it unchanged at a version above every one spent;
// the store then opens under the new passkey alone, the old passkey's
// signatures count for nothing, and Rekey refuses while a loosening waits
// (slice c, NET-4 Enrolment and recovery).
func TestRekeyKeepsPolicyUnderNewPasskey(t *testing.T) {
	e, a, store := opened(t)
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: "a.example"}, 1); err != nil {
		t.Fatal(err)
	}
	b := newAuthenticator(t, rp)
	keep := func(v uint64, f func(*Document)) Proposal {
		d := e.Current()
		d.Version = v
		if f != nil {
			f(&d)
		}
		return Proposal{Doc: d, Diff: []byte("keep")}
	}
	// A loosening waiting blocks it.
	if _, err := a.propose(t, e, Proposal{Doc: edit(5, func(d *Document) { d.Destinations = append(d.Destinations, "x.example") }), Diff: []byte("v5")}, Wait); err != nil {
		t.Fatal(err)
	}
	p := keep(10, nil)
	if err := e.Rekey(b.Public(), p, sign(t, b, b.Public(), p)); !errors.Is(err, ErrPending) {
		t.Errorf("rekey with a loosening waiting: %v", err)
	}
	if err := e.Disown(); !errors.Is(err, ErrPending) {
		t.Errorf("disown with a loosening waiting: %v", err)
	}
	if err := e.Cancel(e.Pending()[0].ID); err != nil {
		t.Fatal(err)
	}
	before := e.Current()
	for name, c := range map[string]struct {
		p   Proposal
		sig func(Proposal) []byte
	}{
		"changed":      {keep(11, func(d *Document) { d.Destinations = nil }), func(p Proposal) []byte { return sign(t, b, b.Public(), p) }},
		"not rising":   {keep(5, nil), func(p Proposal) []byte { return sign(t, b, b.Public(), p) }},
		"old passkey":  {keep(12, nil), func(p Proposal) []byte { return sign(t, a, b.Public(), p) }},
		"no signature": {keep(13, nil), func(Proposal) []byte { return nil }},
	} {
		if err := e.Rekey(b.Public(), c.p, c.sig(c.p)); err == nil {
			t.Errorf("%s: rekeyed", name)
		}
	}
	p = keep(20, nil)
	if err := e.Rekey(b.Public(), p, sign(t, b, b.Public(), p)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.Current().Destinations, before.Destinations) || e.Current().Version != 20 {
		t.Fatalf("rekey changed the policy: %+v", e.Current())
	}
	if _, err := Open(a.Public(), store); err == nil {
		t.Error("the store still opens under the old passkey")
	}
	e2, err := Open(b.Public(), store)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Current().Version != 20 {
		t.Errorf("reopened at %d", e2.Current().Version)
	}
	next := Proposal{Doc: edit(30, func(d *Document) { d.Destinations = append(d.Destinations, "y.example") }), Diff: []byte("v30")}
	if _, err := a.propose(t, e2, next, Wait); !errors.Is(err, ErrBadSig) && !errors.Is(err, ErrNotOwner) {
		t.Errorf("old passkey after rekey: %v", err)
	}
	if _, err := b.propose(t, e2, next, Wait); err != nil {
		t.Errorf("new passkey after rekey: %v", err)
	}
}

// TestDisownRefusesProposals: a disowned engine takes no signed proposal,
// still takes tightenings, and an empty engine takes a passkey with no
// signature, since it holds nothing to carry.
func TestDisownRefusesProposals(t *testing.T) {
	e, a, _ := opened(t)
	if err := e.Disown(); err != nil {
		t.Fatal(err)
	}
	p := Proposal{Doc: edit(5, func(d *Document) { d.Destinations = append(d.Destinations, "x.example") }), Diff: []byte("v5")}
	if _, err := a.propose(t, e, p, Wait); !errors.Is(err, ErrNotOwner) {
		t.Errorf("proposal to a disowned engine: %v", err)
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: "a.example"}, 1); err != nil {
		t.Errorf("tightening on a disowned engine: %v", err)
	}
	if err := e.Rekey(a.Public(), Proposal{}, nil); err == nil {
		t.Error("a held policy changed passkey with no signature")
	}
	empty, err := Open(key.PublicKey{}, &memStore{})
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.Rekey(a.Public(), Proposal{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.propose(t, empty, Proposal{Doc: home(1), Diff: []byte("v1")}, 0); err != nil {
		t.Errorf("first proposal after an empty rekey: %v", err)
	}
}
