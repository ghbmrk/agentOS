package kernel_test

// REQ: KRN-12, KEY-3, KEY-4, KEY-6

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/decoy"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// decoyRange is a synthetic decoy range for the table's destinations.
var decoyRange = []netip.Addr{netip.MustParseAddr("192.168.77.200"), netip.MustParseAddr("192.168.77.201")}

// honeySeed makes the tables' honey key, so a test can play the intruder
// who found it and its issuer's key.
var honeySeed = [ed25519.SeedSize + 4]byte{9, 9, 9}

// decoys logs a table with a honey key at first boot and returns it.
func (r *rig) decoys() decoy.Table {
	r.t.Helper()
	honey := decoy.Own{Kind: decoy.KHoneyKey, Place: decoy.PPlannerView, Make: func(io.Reader) (string, error) {
		return kernel.HoneyKey(bytes.NewReader(honeySeed[:]))
	}}
	tb, err := decoy.Generate(rand.NewChaCha8([32]byte{7}), decoyRange, honey)
	must(r.t, err)
	must(r.t, r.k.LogDecoyTable(0, tb))
	if err := r.k.LogDecoyTable(0, tb); !errors.Is(err, kernel.ErrDecoysSet) {
		r.t.Fatalf("a second table: %v", err)
	}
	return tb
}

// entry is the table's first entry placed at p.
func entry(t *testing.T, tb decoy.Table, p decoy.Place) decoy.Entry {
	t.Helper()
	for _, e := range tb.Entries() {
		if e.Place == p {
			return e
		}
	}
	t.Fatalf("no entry at %s", p)
	return decoy.Entry{}
}

// trips checks the log holds want trips, each with one text, and returns the last.
func (r *rig) trips(want int) kernel.Trip {
	r.t.Helper()
	ts, texts := r.k.State().Trips(), r.k.State().SecurityTexts()
	if len(ts) != want || len(texts) != want {
		r.t.Fatalf("%d trips and %d texts, want %d", len(ts), len(texts), want)
	}
	r.replays()
	return ts[want-1]
}

// sessionOnly checks a session-only trip: task stopped ended, task alive
// still plans, nothing paused and planning goes on.
func (r *rig) sessionOnly(stopped, alive string, at int64) {
	r.t.Helper()
	if _, ok := r.k.State().Task(stopped, at); ok {
		r.t.Fatalf("session %s still live", stopped)
	}
	if r.k.State().Tripped() || len(r.k.State().Changes.Paused) != 0 {
		r.t.Fatal("a session-only trip paused keys or stopped planning")
	}
	id := "after-" + stopped
	r.plan(id, r.serve(alive), st(key.Trash, "m9"))
	if r.status(id) != kernel.SActive {
		r.t.Fatalf("a plan of session %s is %s: planning stopped box-wide", alive, r.status(id))
	}
}

// A honey key, or one derived from it, is refused and logs a trip that
// stops only its session (KRN-12 Trips, Response). Catches a careless
// planner stopping the box, or a honey key that authorizes.
func TestHoneyKeyTripsSessionOnly(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	must(t, r.k.OpenTask(0, "t1"))
	must(t, r.k.OpenTask(0, "t2"))
	r.plan("p0", r.serve("t1"), st(key.Trash, "m0"))

	var honey key.Key
	must(t, json.Unmarshal([]byte(entry(t, tb, decoy.PPlannerView).Value), &honey))
	// The intruder holds the honey key's issuer (no passkey of this box)
	// and derives a key for session t1 from it.
	issuer := key.Ed25519Signer(ed25519.NewKeyFromSeed(honeySeed[:ed25519.SeedSize]))
	intruder := gen(40)
	hk, err := key.ClerkKey(honey, issuer, intruder.pub, 0, 1<<20, key.LimitTask("t1"))
	must(t, err)
	p := kernel.SignPlan(kernel.Plan{ID: "p1", Key: hk, Steps: []kernel.PlanStep{st(key.Trash, "m1")}}, intruder.priv)
	must(t, r.k.Submit(1, p))
	if r.status("p1") != kernel.SRejected || r.k.State().Plans["p1"].Reject != kernel.CTrip {
		t.Fatalf("honey plan %s/%s, want rejected as a trip", r.status("p1"), r.k.State().Plans["p1"].Reject)
	}
	tr := r.trips(1)
	if tr.Cause != kernel.CauseHoneyKey || tr.Response != kernel.RespSession || tr.Session != "t1" || tr.Plan != "p1" {
		t.Fatalf("trip %+v", tr)
	}
	if r.status("p0") != kernel.SCancelled {
		t.Fatalf("the stopped session's plan is %s", r.status("p0"))
	}
	r.sessionOnly("t1", "t2", 2)

	// The bare honey root, with no session, is refused and trips too.
	must(t, r.k.Submit(3, kernel.Plan{ID: "p2", Key: honey, Steps: []kernel.PlanStep{st(key.Trash, "m2")}}))
	if r.k.State().Plans["p2"].Reject != kernel.CTrip || r.trips(2).Session != "" || r.k.State().Tripped() {
		t.Fatal("a bare honey root did not trip, or tripped box-wide")
	}
}

// A fetched page that makes a planner name the metadata address or the
// decoy range, in any form that carries an IPv4 address, zoned or not, refuses that step and stops only that session (KRN-12
// Response). Catches an injected page stopping the box.
func TestHostilePageDecoyDestinationStopsSessionOnly(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	rng := entry(t, tb, decoy.PSandboxEnv).Dest
	dests := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"https://[::ffff:" + rng.String() + "]:8443/",
		"[64:ff9b::" + rng.String() + "]:22",
		rng.String(),
		"http://[64:ff9b::a9fe:a9fe%25eth0]/latest/meta-data/",
		"http://[2002:a9fe:a9fe::1]/",
	}
	for i, dest := range dests {
		s1, s2 := "a"+string(rune('0'+i)), "b"+string(rune('0'+i))
		must(t, r.k.OpenTask(int64(i), s1))
		must(t, r.k.OpenTask(int64(i), s2))
		id := "page" + s1
		r.plan(id, r.serve(s1), st(key.Organize, dest))
		if r.k.State().Plans[id].Reject != kernel.CTrip {
			t.Fatalf("%s: plan %s, want refused as a trip", dest, r.status(id))
		}
		if tr := r.trips(i + 1); tr.Cause != kernel.CauseDest || tr.Response != kernel.RespSession || tr.Session != s1 {
			t.Fatalf("%s: trip %+v", dest, tr)
		}
		r.sessionOnly(s1, s2, int64(i))
	}
	// A public address and a name trip nothing: a name is checked where it
	// is resolved.
	must(t, r.k.OpenTask(9, "c"))
	r.plan("fine", r.serve("c"), st(key.Organize, "https://169.254.169.254.example/"), st(key.Organize, "8.8.8.8"))
	if r.status("fine") != kernel.SActive || len(r.k.State().Trips()) != len(dests) {
		t.Fatalf("a public address or a name tripped: %s", r.status("fine"))
	}
}

// A host-placed decoy value, or one with no planner session behind it, in an
// outbound request pauses that scope's keys before the request leaves, stops
// planning, logs one trip and queues one text (KRN-12 Response). Catches a
// decoy that leaves.
func TestOutboundDecoyPausesScope(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	host := entry(t, tb, decoy.PHostDotfile)
	ok := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "other"}), 1<<40)
	must(t, r.k.OpenTask(0, "t1"))

	// A host value, even from a planner session, in the step's content.
	step := st(key.Send, "x@example.com")
	step.Content = "here is the key: " + base64.StdEncoding.EncodeToString([]byte(host.Value))
	r.plan("p1", r.serve("t1"), step)
	must(t, r.tick(1))
	if r.status("p1") != kernel.SRejected {
		t.Fatalf("plan %s: the request left", r.status("p1"))
	}
	tr := r.trips(1)
	if tr.Cause != kernel.CauseValue || tr.Response != kernel.RespFull || len(tr.Scopes) == 0 {
		t.Fatalf("trip %+v", tr)
	}
	ch := r.k.State().Changes
	for _, id := range tr.Scopes {
		if !ch.Paused[id] {
			t.Fatalf("scope %s not paused", id)
		}
	}
	if !r.k.State().Tripped() {
		t.Fatal("planning not stopped")
	}
	if rf := r.admits("p2", ok, 2); rf == nil || rf.Code != kernel.CTripped {
		t.Fatalf("a plan under another key after a full trip: %v", rf)
	}
	if err := r.k.OpenTask(2, "t2"); !errors.Is(err, kernel.ErrTaskOpen) {
		t.Fatalf("a task opened after a full trip: %v", err)
	}

	// A sandbox value with no planner session gets the full response too.
	r2 := newRig(t)
	tb2 := r2.decoys()
	r2.plan("q1", r2.ck, st(key.Trash, entry(t, tb2, decoy.PSandboxEnv).Value))
	if tr := r2.trips(1); tr.Response != kernel.RespFull || !r2.k.State().Tripped() {
		t.Fatalf("sandbox value with no session: %+v", tr)
	}
}

// A sandbox- or view-placed decoy value that a planner session sends
// outbound, as injected content can make it, is refused before it leaves and
// stops only that session, with one trip and one text; planning goes on.
// Catches an injected page stopping planning box-wide.
func TestSandboxDecoyFromInjectionStopsSessionOnly(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	vals := []string{entry(t, tb, decoy.PSandboxEnv).Value, entry(t, tb, decoy.PPlannerView).Value}
	for i, v := range vals {
		s1, s2 := "a"+string(rune('0'+i)), "b"+string(rune('0'+i))
		must(t, r.k.OpenTask(int64(i), s1))
		must(t, r.k.OpenTask(int64(i), s2))
		id := "inj" + s1
		step := st(key.Send, "x@example.com")
		step.Args["body"] = "token=" + v
		r.plan(id, r.serve(s1), step)
		if r.status(id) != kernel.SRejected {
			t.Fatalf("value %d: plan %s", i, r.status(id))
		}
		if tr := r.trips(i + 1); tr.Cause != kernel.CauseValue || tr.Response != kernel.RespSession || tr.Session != s1 {
			t.Fatalf("value %d: trip %+v", i, tr)
		}
		r.sessionOnly(s1, s2, int64(i))
	}
}

// A trip's pause lifts only with a live passkey's signature over the newest
// trip; a texted RESUME or an unpause is refused with fixed wording (KRN-12
// Response, KEY-4, CH-11). Catches an intruder holding the owner's number
// undoing the pause.
func TestTripResumeNeedsPasskey(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	r.plan("p1", r.ck, st(key.Trash, entry(t, tb, decoy.PHostEnv).Value))
	tr := r.trips(1)
	root := tr.Scopes[0]

	if err := r.k.Resume(1, r.k.State().Stops); !errors.Is(err, kernel.ErrTripResume) {
		t.Fatalf("texted RESUME: %v", err)
	}
	if err := r.k.Unpause(1, root); !errors.Is(err, kernel.ErrTripResume) {
		t.Fatalf("unpause: %v", err)
	}
	if kernel.ErrTripResume.Error() != "A decoy was used, so I paused what it touched. Only your passkey on the owner page lifts that pause; a texted RESUME does not." {
		t.Fatal("the refusal's wording changed")
	}
	n, last, ok := r.k.State().TripResume()
	if !ok || last != tr.Seq {
		t.Fatalf("resume names %d %d %v", n, last, ok)
	}
	for name, c := range map[string]key.Cosign{
		"not a passkey":  key.Approve(r.holder.pass, kernel.TripResumeHash(n, last)),
		"a stale number": key.Approve(r.owner.pass, kernel.TripResumeHash(n+1, last)),
		"an older trip":  key.Approve(r.owner.pass, kernel.TripResumeHash(n, last-1)),
	} {
		if err := r.k.ResumeTrip(2, c); !errors.Is(err, kernel.ErrTripSig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if !r.k.State().Tripped() || !r.k.State().Changes.Paused[root] {
		t.Fatal("a refused resume lifted the pause")
	}
	// Entries written past the kernel lift nothing either: an unpause, a
	// RESUME, or a trip resume no passkey signed, folded on replay.
	es := r.k.Log().Entries()
	for _, f := range []struct{ typ, body string }{
		{kernel.TKeyResumed, `{"id":"` + root.String() + `"}`},
		{kernel.TResume, `{}`},
		{kernel.TTripResumed, `{"n":0,"last":` + fmt.Sprint(last) + `}`},
	} {
		last := es[len(es)-1]
		es = append(es, kernel.Entry{Seq: last.Seq + 1, At: last.At, Type: f.typ, V: 1, Body: json.RawMessage(f.body)})
	}
	if re, err := kernel.Replay(r.anchors(), es); err != nil || !re.Tripped() || !re.Changes.Paused[root] {
		t.Fatalf("forged entries lifted a trip's pause: %v", err)
	}

	// A signature made before a later trip does not lift that trip.
	early := key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))
	r.plan("p2", r.ck, st(key.Trash, entry(t, tb, decoy.PHostJackpot).Value))
	if err := r.k.ResumeTrip(3, early); !errors.Is(err, kernel.ErrTripSig) {
		t.Fatalf("a resume signed before the newest trip: %v", err)
	}
	n, last, _ = r.k.State().TripResume()
	must(t, r.k.ResumeTrip(4, key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))))
	if r.k.State().Tripped() || r.k.State().Changes.Paused[root] {
		t.Fatal("the passkey did not lift the pause")
	}
	r.plan("p3", r.ck, st(key.Trash, "m3"))
	if r.status("p3") != kernel.SActive {
		t.Fatalf("planning after the resume: %s", r.status("p3"))
	}
	if err := r.k.ResumeTrip(5, key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))); err == nil {
		t.Fatal("a resume replayed")
	}
	r.replays()
}

// A core connection refused at a decoy address is logged as a trip that
// stops only that call (KRN-12 Trips).
func TestCallTripStopsCallOnly(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	for _, a := range []string{"169.254.169.254", "::ffff:" + tb.Entries()[0].Dest.String(), "64:ff9b::" + tb.Entries()[0].Dest.String()} {
		must(t, r.k.CallTrip(1, kernel.ExitEgress, netip.MustParseAddr(a)))
	}
	if err := r.k.CallTrip(1, kernel.ExitEgress, netip.MustParseAddr("8.8.8.8")); !errors.Is(err, kernel.ErrNoDecoy) {
		t.Fatalf("a public address: %v", err)
	}
	if err := r.k.CallTrip(1, kernel.ExitKernel, netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Fatal("a call trip claimed the kernel's own exit")
	}
	if tr := r.trips(3); tr.Response != kernel.RespCall || r.k.State().Tripped() {
		t.Fatalf("trip %+v stopped more than the call", tr)
	}
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	if r.status("p1") != kernel.SActive {
		t.Fatal("planning stopped")
	}
}

// A trip entry written past the kernel folds only when it names a table
// entry, and an exit name is short; resumes count up, so each signs anew.
func TestTripEntryBounds(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	n := tb.Len()
	es := r.k.Log().Entries()
	for _, id := range []int{-1, 0, n - 1, n} {
		last := es[len(es)-1]
		es = append(es, kernel.Entry{Seq: last.Seq + 1, At: last.At, Type: kernel.TTrip, V: 1,
			Body: json.RawMessage(fmt.Sprintf(`{"cause":"destination","exit":"egress","entry":%d,"response":"call"}`, id))})
	}
	re, err := kernel.Replay(r.anchors(), es)
	must(t, err)
	if ts := re.Trips(); len(ts) != 2 || ts[0].Entry != 0 || ts[1].Entry != n-1 {
		t.Fatalf("folded trips %+v, want entries 0 and %d only", ts, n-1)
	}

	exit := "e" + strings.Repeat("x", 31)
	must(t, r.k.CallTrip(1, exit, decoy.Metadata))
	if err := r.k.CallTrip(1, exit+"x", decoy.Metadata); err == nil {
		t.Fatal("a 33-byte exit name")
	}

	for i := 0; i < 2; i++ {
		r.plan(fmt.Sprintf("full%d", i), r.ck, st(key.Trash, entry(t, tb, decoy.PHostEnv).Value))
		n, last, ok := r.k.State().TripResume()
		if !ok || n != i {
			t.Fatalf("resume %d is numbered %d", i, n)
		}
		must(t, r.k.ResumeTrip(2, key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))))
	}
}

// A plan that cites decoys of different weights gets the strongest response
// any of them needs: a host value beside a sandbox value or a honey key is
// the full response, and a honey key beside a sandbox value stays
// session-only (KRN-12 Response). Catches a weaker decoy listed first
// masking a breach.
func TestStrongestDecoyResponseWins(t *testing.T) {
	// A sandbox value then a host value, from a planner session.
	r := newRig(t)
	tb := r.decoys()
	sandbox, host := entry(t, tb, decoy.PSandboxEnv), entry(t, tb, decoy.PHostDotfile)
	must(t, r.k.OpenTask(0, "t1"))
	r.plan("p1", r.serve("t1"), st(key.Trash, sandbox.Value), st(key.Trash, host.Value))
	if tr := r.trips(1); tr.Response != kernel.RespFull || tr.Entry == entryIndex(t, tb, sandbox) || len(tr.Scopes) == 0 {
		t.Fatalf("sandbox then host value: trip %+v", tr)
	}
	if !r.k.State().Tripped() {
		t.Fatal("planning not stopped")
	}

	// A honey key with a host value, and with a sandbox value.
	for i, c := range []struct {
		value string
		full  bool
	}{{host.Value, true}, {sandbox.Value, false}} {
		r := newRig(t)
		tb := r.decoys()
		must(t, r.k.OpenTask(0, "t1"))
		must(t, r.k.OpenTask(0, "t2"))
		var honey key.Key
		must(t, json.Unmarshal([]byte(entry(t, tb, decoy.PPlannerView).Value), &honey))
		issuer := key.Ed25519Signer(ed25519.NewKeyFromSeed(honeySeed[:ed25519.SeedSize]))
		intruder := gen(40)
		hk, err := key.ClerkKey(honey, issuer, intruder.pub, 0, 1<<20, key.LimitTask("t1"))
		must(t, err)
		must(t, r.k.Submit(1, kernel.SignPlan(kernel.Plan{ID: "h", Key: hk, Steps: []kernel.PlanStep{st(key.Trash, c.value)}}, intruder.priv)))
		tr := r.trips(1)
		switch {
		case c.full && (tr.Response != kernel.RespFull || tr.Cause != kernel.CauseValue || !r.k.State().Tripped()):
			t.Fatalf("%d: honey key and host value: trip %+v", i, tr)
		case !c.full && (tr.Response != kernel.RespSession || tr.Cause != kernel.CauseHoneyKey || tr.Session != "t1"):
			t.Fatalf("%d: honey key and sandbox value: trip %+v", i, tr)
		}
		if !c.full {
			r.sessionOnly("t1", "t2", 2)
		}
	}
}

// entryIndex is e's index in tb.
func entryIndex(t *testing.T, tb decoy.Table, e decoy.Entry) int {
	t.Helper()
	for i, x := range tb.Entries() {
		if x == e {
			return i
		}
	}
	t.Fatal("no such entry")
	return -1
}
