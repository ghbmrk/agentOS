package kernel_test

// REQ: HW-15, HW-17, REC-2, KRN-1, KEY-7

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// hello is the hello edge sends on a connection whose exporter value is
// nonce (brief decision 5).
func hello(edge pair, nonce byte) (ed25519.PublicKey, []byte, []byte) {
	n := make([]byte, kernel.HelloNonce)
	n[0] = nonce
	return edge.pub, n, ed25519.Sign(edge.priv, kernel.HelloMsg(n))
}

// candidate has the link port report edge's hello at now.
func candidate(r *rig, now int64, edge pair, nonce byte) error {
	k, n, sig := hello(edge, nonce)
	return r.k.EdgeCandidate(now, k, n, sig)
}

// enrolSig is by's signature over enrolling edge as the next edge change,
// replacing whatever is live at this head.
func enrolSig(r *rig, by pair, edge pair) key.Cosign {
	s := r.k.State()
	return key.Approve(by.pass, kernel.EdgeEnrollHash(s.EdgeChanges(), r.k.Box(), edge.pub, s.LiveEdge(r.k.Box())))
}

// enrol takes edge through the page step: its hello, then a hardware key's signature.
func enrol(r *rig, now int64, edge pair, nonce byte) {
	r.t.Helper()
	must(r.t, candidate(r, now, edge, nonce))
	must(r.t, r.k.EdgeEnroll(now, edge.pub, enrolSig(r, r.owner, edge)))
}

func live(r *rig) ed25519.PublicKey { return r.k.State().LiveEdge(r.k.Box()) }

// reopen restarts the rig's kernel over its log, under head. A new head key
// is a restore: its anchor starts from the restored log's head, signed by
// the new key.
func reopen(r *rig, head pair, anchors []key.PublicKey) {
	r.t.Helper()
	if !head.pub.Equal(r.head.pub) {
		es := r.k.Log().Entries()
		r.anchor = &flakyAnchor{MemAnchor: &kernel.MemAnchor{}}
		must(r.t, r.anchor.Put(kernel.SignHead(head.priv, es[len(es)-1].Seq, es[len(es)-1].Hash())))
	}
	r.head = head
	l, err := kernel.Open(cfg(r))
	must(r.t, err)
	r.k, err = kernel.Boot(l, anchors, nil, 0)
	must(r.t, err)
}

// edgeReplays checks the rig's log re-derives every edge decision.
func edgeReplays(r *rig, anchors []key.PublicKey) kernel.Rederived {
	r.t.Helper()
	got, err := kernel.Rederive(anchors, r.k.Log().Entries())
	must(r.t, err)
	return got
}

// The first key is logged by setup only, as sequence 2 right after the
// sequence-1 anchors.set; the fold refuses one anywhere else, so the window
// never reopens. Mutant: drop `e.Seq == 2` from firstOK and the late first
// folds; make SetupWithEdge return before edgeFirst and the logged first
// key is missing.
func TestFirstEdgeOnlyAtSetup(t *testing.T) {
	s := newSetupRig(t)
	edge := gen(40)
	must(t, s.k.SetupWithEdge(1, s.first(), edge.pub))
	es := s.k.Log().Entries()
	if len(es) != 2 || es[0].Type != kernel.TAnchorsSet || es[1].Type != kernel.TEdgeEnrolled || es[1].Seq != 2 {
		t.Fatalf("setup logged %v", es)
	}
	if got := live(s.rig); !got.Equal(edge.pub) {
		t.Fatalf("live edge %x, want the first key", got)
	}
	if h, ok := s.anchor.Latest(); !ok || h.Seq != 2 {
		t.Fatal("the first key is not anchored at setup")
	}
	s.reboot()
	if !live(s.rig).Equal(edge.pub) {
		t.Fatal("the first key is not live after a restart")
	}
	edgeReplays(s.rig, nil)

	// Setup with a malformed first key logs nothing, not even the anchors.
	s2 := newSetupRig(t)
	if err := s2.k.SetupWithEdge(1, s2.first(), edge.pub[:31]); !errors.Is(err, kernel.ErrEdgeKey) || s2.k.Log().Len() != 0 {
		t.Fatalf("a short first key: %v, %d entries", err, s2.k.Log().Len())
	}
	// Setup with no edge logs no first key.
	must(t, s2.k.Setup(1, s2.first()))
	if s2.k.Log().Len() != 1 || live(s2.rig) != nil {
		t.Fatal("setup with no edge logged an edge")
	}

	// A first key anywhere else is not this box's log.
	f := s.first()
	setup := kernel.Entry{Seq: 1, Type: kernel.TAnchorsSet, V: 1, Body: mustJSON(t, f)}
	first := func(seq uint64) kernel.Entry {
		return kernel.Entry{Seq: seq, Type: kernel.TEdgeEnrolled, V: 1,
			Body: mustJSON(t, map[string]any{"key": []byte(edge.pub), "head": []byte(s.head.pub), "first": true})}
	}
	stop := func(seq uint64) kernel.Entry {
		return kernel.Entry{Seq: seq, Type: kernel.TStop, V: 1, Body: []byte("{}")}
	}
	for name, es := range map[string][]kernel.Entry{
		"third, after setup":    {setup, stop(2), first(3)},
		"second, store anchors": {stop(1), first(2)},
		"first of the log":      {first(1)},
		"twice":                 {setup, first(2), first(3)},
	} {
		anchors := []key.PublicKey(nil)
		if name == "second, store anchors" {
			anchors = []key.PublicKey{s.owner.pk, s.spare.pk}
		}
		if _, err := kernel.Replay(anchors, es); !errors.Is(err, kernel.ErrCorrupt) {
			t.Errorf("%s: got %v, want ErrCorrupt", name, err)
		}
	}
	if _, err := kernel.Replay(nil, []kernel.Entry{setup, first(2)}); err != nil {
		t.Fatalf("the first key in its place: %v", err)
	}
}

// A later edge needs a hardware key's signature over the next edge change;
// the entry that makes it live revokes the key it replaces. Mutant: drop
// `key.In(s.Anchors, ...)` in enrollOK and the phone's signature enrols;
// drop the `replaces` revocation in applyEdge and the old key is still
// re-enrollable (the last check fails).
func TestEnrollNeedsAnAnchorAndCutsTheOld(t *testing.T) {
	r := newRig(t)
	phone, old, next := gen(8), gen(41), gen(42)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	enrol(r, 1, old, 1)
	if !live(r).Equal(old.pub) {
		t.Fatal("the first page-step enrolment is not live")
	}
	must(t, candidate(r, 70_000, next, 2))
	n := r.k.State().EdgeChanges()
	for name, c := range map[string]key.Cosign{
		"none":          {},
		"anchor no sig": {By: r.owner.pk},
		"phone passkey": enrolSig(r, phone, next),
		"stale count":   key.Approve(r.owner.pass, kernel.EdgeEnrollHash(n-1, r.k.Box(), next.pub, old.pub)),
		"no replaces":   key.Approve(r.owner.pass, kernel.EdgeEnrollHash(n, r.k.Box(), next.pub, nil)),
		"another head":  key.Approve(r.owner.pass, kernel.EdgeEnrollHash(n, gen(9).pub, next.pub, old.pub)),
		"line domain":   key.Approve(r.owner.pass, kernel.LineHash(n, 300)),
	} {
		before := r.k.Log().Len()
		if err := r.k.EdgeEnroll(70_000, next.pub, c); !errors.Is(err, kernel.ErrEdgeSig) {
			t.Fatalf("%s: %v", name, err)
		}
		if r.k.Log().Len() != before || !live(r).Equal(old.pub) {
			t.Fatalf("%s: a refused enrolment logged or took effect", name)
		}
	}
	must(t, r.k.EdgeEnroll(70_000, next.pub, enrolSig(r, r.spare, next)))
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TEdgeEnrolled || !kernel.Widening(last.Type) {
		t.Fatalf("logged %s, want the widening %s", last.Type, kernel.TEdgeEnrolled)
	}
	if h, ok := r.anchor.Latest(); !ok || h.Seq != uint64(len(es)) {
		t.Fatal("an enrolment is not anchored at once")
	}
	if !live(r).Equal(next.pub) || !r.k.State().EdgeRevoked(old.pub) || r.k.State().EdgeRevoked(next.pub) {
		t.Fatal("the replacement left the old key live or unrevoked")
	}
	if err := candidate(r, 200_000, old, 3); !errors.Is(err, kernel.ErrEdgeRevoked) {
		t.Fatalf("the replaced key's hello: %v", err)
	}
	edgeReplays(r, r.anchors())
}

// A revoked or replaced key never comes back, under this head key or a
// restored one's (KEY-7). Mutant: drop the `s.edge.revoked[...]` test in
// enrollOK and a forged enrolment of the revoked key folds (the replay check).
func TestRevokedNeverReturns(t *testing.T) {
	r := newRig(t)
	a, b := gen(43), gen(44)
	enrol(r, 1, a, 1)
	must(t, r.k.EdgeRevoke(2, a.pub))
	if live(r) != nil || !r.k.State().EdgeRevoked(a.pub) {
		t.Fatal("a revoked key is still live")
	}
	if err := r.k.EdgeRevoke(3, a.pub); !errors.Is(err, kernel.ErrEdgeRevoked) {
		t.Fatalf("revoked twice: %v", err)
	}
	if err := candidate(r, 100_000, a, 2); !errors.Is(err, kernel.ErrEdgeRevoked) {
		t.Fatalf("a revoked key's hello: %v", err)
	}
	if err := r.k.EdgeEnroll(100_000, a.pub, enrolSig(r, r.owner, a)); !errors.Is(err, kernel.ErrEdgeRevoked) {
		t.Fatalf("a revoked key re-enrolled: %v", err)
	}
	enrol(r, 200_000, b, 3)

	// A forged log that re-enrols a, signed correctly and as a candidate,
	// folds to nothing, at this head or another.
	for _, head := range []pair{r.head, gen(50)} {
		s := r.k.State()
		forged := append(r.k.Log().Entries(),
			entryAt(t, s.Seq+1, 300_000, kernel.TEdgeCandidate, helloBody(a, 9)),
		)
		replaced := s.LiveEdge(head.pub)
		forged = append(forged, entryAt(t, s.Seq+2, 300_000, kernel.TEdgeEnrolled, map[string]any{
			"key": []byte(a.pub), "head": []byte(head.pub), "replaces": []byte(replaced),
			"sig": key.Approve(r.owner.pass, kernel.EdgeEnrollHash(s.EdgeChanges(), head.pub, a.pub, replaced)),
		}))
		st, err := kernel.Replay(r.anchors(), forged)
		must(t, err)
		if st.LiveEdge(head.pub).Equal(a.pub) {
			t.Fatal("a forged re-enrolment of a revoked key folded")
		}
		if _, err := kernel.Rederive(r.anchors(), forged); err == nil {
			t.Fatal("rederive passed a revoked key's re-enrolment")
		}
	}

	// Under a restored head key, the re-enrol still refuses.
	reopen(r, gen(51), r.anchors())
	if err := r.k.EdgeEnroll(400_000, a.pub, enrolSig(r, r.owner, a)); !errors.Is(err, kernel.ErrEdgeRevoked) {
		t.Fatalf("a revoked key re-enrolled after a restore: %v", err)
	}
}

// A restored log under a new head key trusts no edge, the restored one
// included, and keeps every revocation (REC-2, BAK-1). Mutant: drop the
// head comparison in State.LiveEdge and the old edge is live after the
// restore.
func TestRestoredLogTrustsNoEdge(t *testing.T) {
	r := newRig(t)
	old, cur := gen(45), gen(46)
	enrol(r, 1, old, 1)
	must(t, candidate(r, 70_000, cur, 2))
	must(t, r.k.EdgeEnroll(70_000, cur.pub, enrolSig(r, r.owner, cur)))
	if !live(r).Equal(cur.pub) {
		t.Fatal("setup of the case failed")
	}
	reopen(r, gen(52), r.anchors())
	if live(r) != nil {
		t.Fatalf("a restored core trusts edge %x", live(r))
	}
	if !r.k.State().EdgeRevoked(old.pub) {
		t.Fatal("a restore lost a revocation")
	}
	// The restore visit's page step enrols the same edge again: its last
	// hello is still the candidate, and the owner signs under the new head.
	if got := r.k.State().PendingEdge(r.k.Box()); !got.Equal(cur.pub) {
		t.Fatalf("pending edge after a restore %x, want the restored one", got)
	}
	must(t, r.k.EdgeEnroll(80_000, cur.pub, enrolSig(r, r.owner, cur)))
	if !live(r).Equal(cur.pub) || r.k.State().EdgeRevoked(cur.pub) {
		t.Fatal("the restore visit did not re-enrol the edge")
	}
	edgeReplays(r, r.anchors())
}

// After edge.cut nothing is live until a page-step enrolment, and the
// logged signature of the enrolment before the cut no longer verifies,
// since the count of edge changes moved (the replay in
// builds/2026-10-26-pr3300-edge-enroll-replay-model.py). Mutant: make
// EdgeEnrollHash ignore n and the replay re-enrols.
func TestCutHoldsUntilEnrol(t *testing.T) {
	r := newRig(t)
	edge := gen(47)
	must(t, candidate(r, 1, edge, 1))
	before := enrolSig(r, r.owner, edge)
	must(t, r.k.EdgeEnroll(1, edge.pub, before))
	if err := r.k.EdgeCut(2, ""); !errors.Is(err, kernel.ErrEdgeSlot) {
		t.Fatalf("a cut naming no slot: %v", err)
	}
	must(t, r.k.EdgeCut(2, "passphrase"))
	if live(r) != nil {
		t.Fatal("an edge is live after an unknown-host start")
	}
	// A restart on the trusted PC again does not revive it.
	reopen(r, r.head, r.anchors())
	if live(r) != nil {
		t.Fatal("a cut edge came back at a restart")
	}
	// The same key is still the pending candidate; the old signature replays.
	if err := r.k.EdgeEnroll(3, edge.pub, before); !errors.Is(err, kernel.ErrEdgeSig) {
		t.Fatalf("a replayed enrolment after a cut: %v", err)
	}
	s := r.k.State()
	forged := append(r.k.Log().Entries(), entryAt(t, s.Seq+1, 3, kernel.TEdgeEnrolled, map[string]any{
		"key": []byte(edge.pub), "head": []byte(r.head.pub), "sig": before,
	}))
	if st, err := kernel.Replay(r.anchors(), forged); err != nil || st.LiveEdge(r.head.pub) != nil {
		t.Fatalf("a forged replay after a cut: %v", err)
	}
	must(t, r.k.EdgeEnroll(4, edge.pub, enrolSig(r, r.owner, edge)))
	if !live(r).Equal(edge.pub) {
		t.Fatal("the page step after a cut did not enrol")
	}
	// A cut with nothing live logs nothing.
	r2 := newRig(t)
	n := r2.k.Log().Len()
	must(t, r2.k.EdgeCut(5, "passphrase"))
	if r2.k.Log().Len() != n {
		t.Fatal("a cut with no edge logged")
	}
	edgeReplays(r, r.anchors())
}

// The owner enrols only the latest logged candidate, which only the link
// port's hello puts in the log; a bad hello, or any second candidate in a
// minute, logs nothing (the flood in
// builds/2026-10-26-pr3300-82c6b60-candidate-flood-model.py). Mutant: drop
// the `at-c.at < CandidateEvery` test in candidateOK and the alternating
// keys log every hello; drop the candidate test in enrollOK and a key the
// owner side substitutes enrols.
func TestEnrollOnlyTheLoggedCandidate(t *testing.T) {
	r := newRig(t)
	a, b, c, stranger := gen(48), gen(49), gen(53), gen(54)
	// No candidate: nothing to enrol, even signed.
	if err := r.k.EdgeEnroll(1, a.pub, enrolSig(r, r.owner, a)); !errors.Is(err, kernel.ErrEdgeCandidate) {
		t.Fatalf("an enrolment with no candidate: %v", err)
	}
	k, n, sig := hello(a, 1)
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	for name, h := range map[string][3][]byte{
		"bad sig":     {k, n, bad},
		"other nonce": {k, append([]byte{2}, n[1:]...), sig},
		"stranger":    {stranger.pub, n, sig},
		"short nonce": {k, n[:31], sig},
		"long key":    {append(append([]byte(nil), k...), 0), n, sig},
	} {
		if err := r.k.EdgeCandidate(1, h[0], h[1], h[2]); err == nil {
			t.Fatalf("%s: a bad hello was logged", name)
		}
	}
	if r.k.State().PendingEdge(r.k.Box()) != nil {
		t.Fatal("a bad hello left a candidate")
	}
	n0 := r.k.Log().Len()
	must(t, candidate(r, 10, a, 1))
	for i, who := range []pair{a, b, c, b, a} {
		if err := candidate(r, int64(20+i), who, byte(10+i)); !errors.Is(err, kernel.ErrEdgeBusy) {
			t.Fatalf("hello %d within the minute: %v", i, err)
		}
	}
	if r.k.Log().Len() != n0+1 {
		t.Fatalf("a minute of hellos logged %d entries", r.k.Log().Len()-n0)
	}
	// The same key again, a minute on, is still not a second candidate.
	if err := candidate(r, 70_000, a, 3); !errors.Is(err, kernel.ErrEdgeBusy) {
		t.Fatalf("the same key's second candidate: %v", err)
	}
	must(t, candidate(r, 70_010, b, 4))
	// a was the candidate; b is now: a signed key that is not b refuses.
	if err := r.k.EdgeEnroll(70_020, a.pub, enrolSig(r, r.owner, a)); !errors.Is(err, kernel.ErrEdgeCandidate) {
		t.Fatalf("an old candidate enrolled: %v", err)
	}
	if err := r.k.EdgeEnroll(70_020, stranger.pub, enrolSig(r, r.owner, stranger)); !errors.Is(err, kernel.ErrEdgeCandidate) {
		t.Fatalf("a key never on the cable enrolled: %v", err)
	}
	must(t, r.k.EdgeEnroll(70_020, b.pub, enrolSig(r, r.owner, b)))
	// The live key's hello is no candidate.
	if err := candidate(r, 200_000, b, 5); !errors.Is(err, kernel.ErrEdgeLive) {
		t.Fatalf("the live key's hello: %v", err)
	}
	edgeReplays(r, r.anchors())
}

// Rederive re-derives every edge decision from the log alone: the same live
// edge and revocations, and a logged enrolment or candidate the entries
// before it refuse is a divergence. Mutant: make derive's edge case skip
// `s.edgeDecision(e)` and the forged entries pass.
func TestEdgeDecisionsRederive(t *testing.T) {
	r := newRig(t)
	a, b := gen(55), gen(56)
	enrol(r, 1, a, 1)
	must(t, r.k.EdgeCut(2, "passphrase"))
	must(t, candidate(r, 70_000, b, 2))
	must(t, r.k.EdgeEnroll(70_000, b.pub, enrolSig(r, r.owner, b)))
	must(t, r.k.EdgeRevoke(70_001, b.pub))
	es := r.k.Log().Entries()
	got := edgeReplays(r, r.anchors())
	if got.Checked[kernel.TEdgeEnrolled] != 2 || got.Checked[kernel.TEdgeCandidate] != 2 ||
		got.Recorded[kernel.TEdgeCut] != 1 || got.Recorded[kernel.TEdgeRevoked] != 1 {
		t.Fatalf("rederived %+v", got)
	}
	st, err := kernel.Replay(r.anchors(), es)
	must(t, err)
	if st.LiveEdge(r.head.pub) != nil || !st.EdgeRevoked(b.pub) || st.EdgeRevoked(a.pub) {
		t.Fatal("the replayed edge state differs")
	}
	// A refused enrolment and a refused candidate written past the kernel.
	n := uint64(len(es))
	for name, e := range map[string]kernel.Entry{
		"unsigned enrol": entryAt(t, n+1, 80_000, kernel.TEdgeEnrolled, map[string]any{"key": []byte(a.pub), "head": []byte(r.head.pub)}),
		"busy candidate": entryAt(t, n+1, 70_001, kernel.TEdgeCandidate, helloBody(a, 7)),
		"bad hello":      entryAt(t, n+1, 200_000, kernel.TEdgeCandidate, map[string]any{"key": []byte(a.pub), "nonce": make([]byte, 32), "sig": make([]byte, 64)}),
	} {
		var d *kernel.Divergence
		if _, err := kernel.Rederive(r.anchors(), append(es[:len(es):len(es)], e)); !errors.As(err, &d) || d.Seq != n+1 {
			t.Errorf("%s: got %v, want a divergence at %d", name, err, n+1)
		}
	}
}

// The edge state survives a restart, and the kinds are a closed, versioned
// set (LOG-5): another version is unknown, and an oversized key refuses.
func TestEdgeEntriesReplay(t *testing.T) {
	for _, typ := range []string{kernel.TEdgeEnrolled, kernel.TEdgeCandidate, kernel.TEdgeRevoked, kernel.TEdgeCut} {
		if !kernel.Known(typ, 1) || kernel.Known(typ, 2) || kernel.Widening(typ) != (typ == kernel.TEdgeEnrolled) {
			t.Fatalf("%s: known %v, widening %v", typ, kernel.Known(typ, 1), kernel.Widening(typ))
		}
	}
	r := newRig(t)
	a, b := gen(57), gen(58)
	enrol(r, 1, a, 1)
	must(t, candidate(r, 70_000, b, 2))
	reopen(r, r.head, r.anchors())
	if !live(r).Equal(a.pub) || !r.k.State().PendingEdge(r.k.Box()).Equal(b.pub) {
		t.Fatal("the edge state did not survive a restart")
	}
	long := append(append([]byte(nil), b.pub...), 0)
	if err := r.k.EdgeRevoke(70_001, long); !errors.Is(err, kernel.ErrEdgeKey) {
		t.Fatalf("an oversized key revoked: %v", err)
	}
	if err := r.k.EdgeEnroll(70_001, long, key.Cosign{}); !errors.Is(err, kernel.ErrEdgeKey) {
		t.Fatalf("an oversized key enrolled: %v", err)
	}
	s := r.k.State()
	if _, err := kernel.Replay(r.anchors(), append(r.k.Log().Entries(),
		entryAt(t, s.Seq+1, 70_002, kernel.TEdgeRevoked, map[string]any{"key": long}))); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("an oversized revoked key folded: %v", err)
	}
}

func helloBody(edge pair, nonce byte) map[string]any {
	k, n, sig := hello(edge, nonce)
	return map[string]any{"key": []byte(k), "nonce": n, "sig": sig}
}

func entryAt(t *testing.T, seq uint64, at int64, typ string, body any) kernel.Entry {
	return kernel.Entry{Seq: seq, At: at, Type: typ, V: 1, Body: mustJSON(t, body)}
}

// An anchor-signed enrolment written past the kernel whose replaces is not
// the live key folds to nothing and diverges, so a forged entry cannot
// leave the old key live and unrevoked beside the new one (L3 probe on
// #3341). Mutant: drop `!s.LiveEdge(b.Head).Equal(b.Replaces) ||` from
// enrollOK and the forged enrolment folds.
func TestEnrollReplacesOnlyTheLiveKey(t *testing.T) {
	r := newRig(t)
	old, next := gen(41), gen(42)
	enrol(r, 1, old, 1)
	must(t, candidate(r, 70_000, next, 2))
	s := r.k.State()
	sig := key.Approve(r.owner.pass, kernel.EdgeEnrollHash(s.EdgeChanges(), r.k.Box(), next.pub, nil))
	es := r.k.Log().Entries()
	forged := entryAt(t, s.Seq+1, 70_001, kernel.TEdgeEnrolled, map[string]any{"key": []byte(next.pub), "head": []byte(r.head.pub), "sig": sig})
	all := append(es[:len(es):len(es)], forged)
	st, err := kernel.Replay(r.anchors(), all)
	must(t, err)
	if !st.LiveEdge(r.head.pub).Equal(old.pub) || st.EdgeRevoked(old.pub) {
		t.Fatalf("an enrolment replacing nothing folded: live %x, old revoked %v", st.LiveEdge(r.head.pub), st.EdgeRevoked(old.pub))
	}
	var d *kernel.Divergence
	if _, err := kernel.Rederive(r.anchors(), all); !errors.As(err, &d) || d.Seq != s.Seq+1 {
		t.Fatalf("got %v, want a divergence at %d", err, s.Seq+1)
	}
}
