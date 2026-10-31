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
	"slices"
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

// trips checks the log holds want trips and the owner line texts, after
// coalescing, and returns the newest.
func (r *rig) trips(want, texts int) kernel.Trip {
	r.t.Helper()
	ts, tx := r.k.State().Trips(), r.k.State().SecurityTexts()
	if len(ts) != want || len(tx) != texts {
		r.t.Fatalf("%d trips and %d texts, want %d and %d", len(ts), len(tx), want, texts)
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
	tr := r.trips(1, 1)
	if tr.Cause != kernel.CauseHoneyKey || tr.Response != kernel.RespSession || tr.Session != "t1" || tr.Plan != "p1" {
		t.Fatalf("trip %+v", tr)
	}
	if r.status("p0") != kernel.SCancelled {
		t.Fatalf("the stopped session's plan is %s", r.status("p0"))
	}
	r.sessionOnly("t1", "t2", 2)

	// The bare honey root, with no session, is refused and trips too.
	must(t, r.k.Submit(3, kernel.Plan{ID: "p2", Key: honey, Steps: []kernel.PlanStep{st(key.Trash, "m2")}}))
	if r.k.State().Plans["p2"].Reject != kernel.CTrip || r.trips(2, 1).Session != "" || r.k.State().Tripped() {
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
		"[::ffff:0:" + rng.String() + "]:443",
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
		if tr := r.trips(i+1, 1); tr.Cause != kernel.CauseDest || tr.Response != kernel.RespSession || tr.Session != s1 {
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
	tr := r.trips(1, 1)
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
	if tr := r2.trips(1, 1); tr.Response != kernel.RespFull || !r2.k.State().Tripped() {
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
		if tr := r.trips(i+1, 1); tr.Cause != kernel.CauseValue || tr.Response != kernel.RespSession || tr.Session != s1 {
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
	tr := r.trips(1, 1)
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

	// Another decoy under the same key during the pause is logged but pauses
	// nothing new, so the signature made before it still stands; one under
	// another key pauses that key too, and the earlier signature no longer
	// lifts it.
	early := key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))
	r.plan("p2", r.ck, st(key.Trash, entry(t, tb, decoy.PHostJackpot).Value))
	if r.k.State().Plans["p2"].Reject != kernel.CTrip || len(r.k.State().Trips()) != 2 {
		t.Fatal("a trip during the pause was not logged")
	}
	if _, l2, _ := r.k.State().TripResume(); l2 != last {
		t.Fatal("a trip that paused nothing new moved the resume")
	}
	other := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "other"}), 1<<40)
	r.plan("p2b", other, st(key.Trash, entry(t, tb, decoy.PHostDotfile).Value))
	if tr := r.trips(3, 2); tr.Response != kernel.RespFull || !r.k.State().Changes.Paused[tr.Scopes[0]] {
		t.Fatalf("a full trip during the pause did not pause its key: %+v", tr)
	}
	if err := r.k.ResumeTrip(3, early); !errors.Is(err, kernel.ErrTripSig) {
		t.Fatalf("a resume signed before a trip that paused another key: %v", err)
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
	if tr := r.trips(3, 1); tr.Response != kernel.RespCall || r.k.State().Tripped() {
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
	if tr := r.trips(1, 1); tr.Response != kernel.RespFull || tr.Entry == entryIndex(t, tb, sandbox) || len(tr.Scopes) == 0 {
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
		tr := r.trips(1, 1)
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

// honeyKey is the table's honey key and a key the intruder derives from it
// for task, signed by the holder it names.
func honeyKey(t *testing.T, tb decoy.Table, task string) (key.Key, key.Key, pair) {
	t.Helper()
	var honey key.Key
	must(t, json.Unmarshal([]byte(entry(t, tb, decoy.PPlannerView).Value), &honey))
	issuer := key.Ed25519Signer(ed25519.NewKeyFromSeed(honeySeed[:ed25519.SeedSize]))
	intruder := gen(40)
	hk, err := key.ClerkKey(honey, issuer, intruder.pub, 0, 1<<20, key.LimitTask(task))
	must(t, err)
	return honey, hk, intruder
}

// While a trip's pause is in force, a hostile session that keeps citing
// honey keys or decoy values under keys already paused still trips (its
// session stops, each trip is logged) but sends no new full text and does
// not move what the owner's resume signs; an exit's call trip meanwhile
// does not void that signature either (KRN-12 Response, KEY-4). Catches an
// intruder keeping the owner from resuming, or a trip lost in a pause.
func TestRepeatTripsDuringAPauseKeepTheResume(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	must(t, r.k.OpenTask(0, "t1"))
	r.plan("full", r.ck, st(key.Trash, entry(t, tb, decoy.PHostEnv).Value))
	r.trips(1, 1)
	n, last, ok := r.k.State().TripResume()
	if !ok {
		t.Fatal("no pause after a full trip")
	}
	signed := key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))

	_, hk, intruder := honeyKey(t, tb, "t1")
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("honey%d", i)
		must(t, r.k.Submit(int64(i), kernel.SignPlan(kernel.Plan{ID: id, Key: hk, Steps: []kernel.PlanStep{st(key.Trash, "m")}}, intruder.priv)))
		r.plan(fmt.Sprintf("again%d", i), r.ck, st(key.Trash, entry(t, tb, decoy.PHostDotfile).Value))
		if r.k.State().Plans[id].Reject != kernel.CTrip {
			t.Fatalf("%s: refused %q, want %q", id, r.k.State().Plans[id].Reject, kernel.CTrip)
		}
	}
	// Keys the session derives afresh share the paused root and account.
	for i := 0; i < 5; i++ {
		r.plan(fmt.Sprintf("derived%d", i), r.derive(key.LimitUses(int64(i+1))), st(key.Trash, entry(t, tb, decoy.PHostJackpot).Value))
	}
	must(t, r.k.CallTrip(30, kernel.ExitEgress, decoy.Metadata))
	if got := len(r.k.State().Trips()); got != 27 {
		t.Fatalf("%d trips logged, want every one of 27", got)
	}
	if got := len(r.k.State().SecurityTexts()); got != 3 {
		t.Fatalf("%d texts, want one full, one session and one call", got)
	}
	if n2, last2, _ := r.k.State().TripResume(); n2 != n || last2 != last {
		t.Fatalf("the resume moved from (%d, %d) to (%d, %d)", n, last, n2, last2)
	}
	must(t, r.k.ResumeTrip(31, signed))
	if r.k.State().Tripped() {
		t.Fatal("the owner's signature did not lift the pause")
	}
	if _, ok := r.k.State().Task("t1", 32); ok {
		t.Fatal("the honey session outlived its trip")
	}
	r.replays()
}

// Session and call trips are each texted once per TextWindow, however many
// repeat in it, and their text says so; a full trip is always texted (KRN-12
// Response, CH-15). Catches a hostile session flooding the owner line, or an
// owner reading one text as one event.
func TestSecurityTextsCoalesce(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	view := entry(t, tb, decoy.PPlannerView).Value
	at := int64(0)
	inject := func(i int) {
		task := fmt.Sprintf("s%d", i)
		must(t, r.k.OpenTask(at, task))
		step := st(key.Send, "x@example.com")
		step.Args["body"] = view
		must(t, r.k.Submit(at, r.sign(kernel.Plan{ID: "inj" + task, Key: r.serve(task), Steps: []kernel.PlanStep{step}})))
	}
	for i := 0; i < 5; i++ {
		inject(i)
		must(t, r.k.CallTrip(at, kernel.ExitEgress, decoy.Metadata))
		at += 1000
	}
	if ts, texts := len(r.k.State().Trips()), len(r.k.State().SecurityTexts()); ts != 10 || texts != 2 {
		t.Fatalf("%d trips gave %d texts, want 10 and 2", ts, texts)
	}
	// A coalesced text says repeats follow unseen, so one text is not read
	// as one event.
	for _, tx := range r.k.State().SecurityTexts() {
		if !strings.HasSuffix(tx.Text, " Repeats this hour are logged, not texted.") {
			t.Fatalf("a coalescing text does not say repeats are logged: %q", tx.Text)
		}
	}
	at += kernel.TextWindow
	inject(9)
	if texts := r.k.State().SecurityTexts(); len(texts) != 3 || texts[2].Trip != r.k.State().Trips()[10].Seq {
		t.Fatalf("a session trip after the window: %d texts", len(texts))
	}
	for i := 0; i < 2; i++ {
		must(t, r.k.Submit(at, r.sign(kernel.Plan{ID: fmt.Sprintf("full%d", i), Key: r.ck, Steps: []kernel.PlanStep{st(key.Trash, entry(t, tb, decoy.PHostEnv).Value)}})))
		n, last, _ := r.k.State().TripResume()
		must(t, r.k.ResumeTrip(at, key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))))
	}
	if texts := r.k.State().SecurityTexts(); len(texts) != 5 {
		t.Fatalf("two full trips in one window: %d texts, want 5", len(texts))
	}
	r.replays()
}

// A plan's trip is logged in its rejection's entry, so no crash can leave
// the plan refused with no pause, stop or text; a trip entry of the plan
// kind written past the kernel folds nothing and is a divergence (KRN-12
// Response, CH-15, KRN-6). Catches a lost breach signal.
func TestPlanTripIsInItsRejection(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	r.plan("p1", r.ck, st(key.Trash, entry(t, tb, decoy.PHostEnv).Value))
	es := r.k.Log().Entries()
	lastE := es[len(es)-1]
	if lastE.Type != kernel.TPlanRejected || !bytes.Contains(lastE.Body, []byte(`"trip"`)) {
		t.Fatalf("the newest entry is %s %s, want the rejection carrying its trip", lastE.Type, lastE.Body)
	}
	for _, e := range es {
		if e.Type == kernel.TTrip {
			t.Fatalf("a plan's trip logged apart: %s", e.Body)
		}
	}
	re, err := kernel.Replay(r.anchors(), es)
	if err != nil || !re.Tripped() || len(re.Trips()) != 1 || re.Trips()[0].Seq != lastE.Seq {
		t.Fatalf("replay of the log up to the rejection: %v", err)
	}

	r2 := newRig(t)
	tb2 := r2.decoys()
	must(t, r2.k.OpenTask(0, "t1"))
	r2.plan("ok", r2.serve("t1"), st(key.Trash, "m1"))
	base := r2.k.Log().Entries()
	ix := entryIndex(t, tb2, entry(t, tb2, decoy.PHostEnv))
	for _, body := range []string{
		fmt.Sprintf(`{"cause":"value","exit":"kernel","entry":%d,"response":"full","plan":"ok"}`, ix),
		fmt.Sprintf(`{"cause":"value","exit":"kernel","entry":%d,"response":"session","plan":"ok","session":"t1"}`, ix),
		// a honey key at Extend or Issue stops no session
		fmt.Sprintf(`{"cause":"honey-key","exit":"kernel","entry":%d,"response":"session","plan":"ok","session":"t1"}`, entryIndex(t, tb2, entry(t, tb2, decoy.PPlannerView))),
	} {
		l := base[len(base)-1]
		es := append(slices.Clone(base), kernel.Entry{Seq: l.Seq + 1, At: l.At, Type: kernel.TTrip, V: 1, Body: json.RawMessage(body)})
		forgedTripFoldsNothing(t, r2, es, body)
	}
	// spend.held is a recorded input, so a forged hold of a live plan
	// before a honey-key session trip naming it must not let that trip in.
	l := base[len(base)-1]
	held := json.RawMessage(`{"plan":"ok","code":"spend-task"}`)
	trip := fmt.Sprintf(`{"cause":"honey-key","exit":"kernel","entry":%d,"response":"session","plan":"ok","session":"t1"}`, entryIndex(t, tb2, entry(t, tb2, decoy.PPlannerView)))
	es = append(slices.Clone(base),
		kernel.Entry{Seq: l.Seq + 1, At: l.At, Type: kernel.TSpendHeld, V: 1, Body: held},
		kernel.Entry{Seq: l.Seq + 2, At: l.At, Type: kernel.TTrip, V: 1, Body: json.RawMessage(trip)})
	forgedTripFoldsNothing(t, r2, es, "a honey trip on a forged hold")
	if re, _ := kernel.Replay(r2.anchors(), es); re.Plans["ok"].Status != kernel.SActive {
		t.Fatalf("a forged trip on a forged hold stopped the plan: %s", re.Plans["ok"].Status)
	}
}

// forgedTripFoldsNothing checks that the trip entry ending es, written past
// the kernel, folds no trip on replay and is a divergence.
func forgedTripFoldsNothing(t *testing.T, r *rig, es []kernel.Entry, what string) {
	t.Helper()
	re, err := kernel.Replay(r.anchors(), es)
	must(t, err)
	if re.Tripped() || len(re.Trips()) != 0 {
		t.Fatalf("a forged trip folded: %s", what)
	}
	var d *kernel.Divergence
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), es); !errors.As(err, &d) {
		t.Fatalf("a forged trip is not a divergence: %s: %v", what, err)
	}
}

// A planner session's plan whose key does not verify, carrying a sandbox or
// view value, stops only the session its key names, never planning box-wide
// (KRN-12 Response). Catches a future submit path that lets injected content
// stop the box.
func TestUnverifiedKeyStopsItsSessionOnly(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	must(t, r.k.OpenTask(0, "t1"))
	must(t, r.k.OpenTask(0, "t2"))
	step := st(key.Send, "x@example.com")
	step.Args["body"] = entry(t, tb, decoy.PPlannerView).Value
	must(t, r.k.Submit(1, kernel.Plan{ID: "unsigned", Key: r.serve("t1"), Steps: []kernel.PlanStep{step}}))
	if tr := r.trips(1, 1); tr.Response != kernel.RespSession || tr.Session != "t1" {
		t.Fatalf("trip %+v", tr)
	}
	r.sessionOnly("t1", "t2", 2)

	// A key that claims no task has no session: the full response.
	must(t, r.k.Submit(3, kernel.Plan{ID: "unsigned2", Key: r.ck, Steps: []kernel.PlanStep{step}}))
	if tr := r.trips(2, 2); tr.Response != kernel.RespFull || !r.k.State().Tripped() {
		t.Fatalf("an unverified key with no task: trip %+v", tr)
	}
}

// A honey key cited through Extend or in an Issue batch is refused and gets
// the full response: both are owner-side calls no planner session makes, so
// planner-view content reached the owner path (KRN-12 Response, "Any other
// decoy value gets the full response"). Extend pauses the honey key's IDs
// and the held plan's scope and funding key, Issue the honey key's IDs; both
// stop planning until the passkey resume. Catches an owner-side breach that
// stops only one request.
func TestHoneyKeyAtOwnerSideTripsFull(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	exhaust(r, "t1", 100)
	honey, hk, _ := honeyKey(t, tb, "t1")
	other := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "other"}), 1<<40)

	var rf *key.Refusal
	if err := r.k.Extend(3, hk, "t1"); !errors.As(err, &rf) || rf.Code != kernel.CTrip {
		t.Fatalf("a honey key extending t1: %v", err)
	}
	tr := r.trips(1, 1)
	if tr.Cause != kernel.CauseHoneyKey || tr.Response != kernel.RespFull || tr.Plan != "t1" || tr.Session != "" {
		t.Fatalf("extend trip %+v", tr)
	}
	ch, p := r.k.State().Changes, r.k.State().Plans["t1"]
	want := append([]key.ID{honey.Tip(), hk.Tip(), r.k.State().SpendHeld["t1"].Funding}, p.Scopes...)
	for _, id := range want {
		if !ch.Paused[id] || !slices.Contains(tr.Scopes, id) {
			t.Fatalf("scope %s not paused by %v", id, tr.Scopes)
		}
	}
	if !r.k.State().Tripped() {
		t.Fatal("planning not stopped")
	}
	if rf := r.admits("p2", other, 4); rf == nil || rf.Code != kernel.CTripped {
		t.Fatalf("a plan under another key after an owner-side trip: %v", rf)
	}
	if r.k.State().SecurityTexts()[0].Text != r.fullText(t) {
		t.Fatal("an owner-side trip sent other than the full text")
	}
	n, last, _ := r.k.State().TripResume()
	must(t, r.k.ResumeTrip(5, key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))))
	if r.k.State().Tripped() {
		t.Fatal("the passkey resume left the trip in force")
	}

	r2 := newRig(t)
	tb2 := r2.decoys()
	honey2, _, _ := honeyKey(t, tb2, "t1")
	if err := r2.k.Issue(4, approve([]key.Key{honey2}, r2.owner, r2.spare), honey2); !errors.As(err, &rf) || rf.Code != kernel.CTrip {
		t.Fatalf("a honey key in an Issue batch: %v", err)
	}
	if tr := r2.trips(1, 1); tr.Response != kernel.RespFull || tr.Plan != "" || !slices.Equal(tr.Scopes, []key.ID{honey2.Tip()}) || !r2.k.State().Tripped() {
		t.Fatalf("issue trip %+v", tr)
	}
	if _, ok := r2.k.State().Grants[honey2.Tip()]; ok {
		t.Fatal("the honey key was granted")
	}
}

// A honey key at Extend on a plan extended once and held again pauses the
// earlier extension's whole chain, the envelope's root and links included,
// and the key funding the hold, as well as the plan's scope (KRN-12
// Response, KEY-6). Catches an owner-side trip that leaves the envelope
// funding a held plan live while planning is stopped (#4241).
func TestHoneyKeyAtExtendPausesTheEarlierExtension(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 100)
	ext := extension(r, env, key.LimitSpendTask(300))
	must(t, r.k.Extend(3, ext, "t1"))
	must(t, r.meter(4, "t1", "api", 300, "provider"))
	rf := r.admit(5, "t1", 1)
	if rf == nil {
		t.Fatal("the extension should be used up")
	}
	must(t, r.k.Hold(5, "t1", rf))
	h := r.k.State().SpendHeld["t1"]
	if h.Funding != ext.Tip() {
		t.Fatalf("the hold is funded by %s, want the extension %s", h.Funding, ext.Tip())
	}
	_, hk, _ := honeyKey(t, tb, "t1")
	if err := r.k.Extend(6, hk, "t1"); !errors.As(err, &rf) || rf.Code != kernel.CTrip {
		t.Fatalf("a honey key extending t1 again: %v", err)
	}
	tr := r.trips(1, 1)
	var want []key.ID
	for i := 0; i <= len(ext.Links); i++ {
		want = append(want, key.Key{Root: ext.Root, Links: ext.Links[:i]}.Tip())
	}
	want = append(want, key.Key{Root: env.Root}.Tip(), env.Tip(), h.Funding)
	want = append(want, r.k.State().Plans["t1"].Scopes...)
	ch := r.k.State().Changes
	for _, id := range want {
		if !ch.Paused[id] || !slices.Contains(tr.Scopes, id) {
			t.Fatalf("%s not paused by %v", id, tr.Scopes)
		}
	}
	if rf := r.admit(7, "t1", 1); rf == nil {
		t.Fatal("the paused extension still funds t1")
	}
}

// fullText is the full response's text, from a host value's trip.
func (r *rig) fullText(t *testing.T) string {
	r2 := newRig(t)
	tb := r2.decoys()
	r2.plan("p", r2.ck, st(key.Trash, entry(t, tb, decoy.PHostEnv).Value))
	return r2.k.State().SecurityTexts()[0].Text
}

// No recorded input alone pauses a key: a trip entry at the kernel's exit,
// a trip.owner entry whose key is no honey key, one whose trip is not the
// one its key derives, and one whose body is not the one the kernel logs
// fold nothing, and Rederive reports each (KRN-6); the derived one folds and
// Rederive accepts it. Catches a forged entry pausing the owner's keys or
// stopping planning, and a body the fold takes that Rederive reports.
func TestOwnerTripIsDerivedAgain(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	honey, _, _ := honeyKey(t, tb, "t1")
	base := r.k.Log().Entries()
	forge := func(typ, body string) []kernel.Entry {
		last := base[len(base)-1]
		return append(slices.Clone(base), kernel.Entry{Seq: last.Seq + 1, At: last.At, Type: typ, V: 1, Body: json.RawMessage(body)})
	}
	hb, _ := json.Marshal(honey)
	cb, _ := json.Marshal(r.ck)
	full := func(scope key.ID) string {
		return fmt.Sprintf(`{"cause":"honey-key","exit":"kernel","entry":%d,"response":"full","scopes":[%q]}`, honeyEntry(t, tb), scope)
	}
	for name, es := range map[string][]kernel.Entry{
		"call trip at the kernel":  forge(kernel.TTrip, fmt.Sprintf(`{"cause":"honey-key","exit":"kernel","entry":%d,"response":"call"}`, honeyEntry(t, tb))),
		"owner trip, no honey key": forge(kernel.TTripOwner, fmt.Sprintf(`{"op":"issue","key":%s,"trip":%s}`, cb, full(r.ck.Tip()))),
		"owner trip, forged scope": forge(kernel.TTripOwner, fmt.Sprintf(`{"op":"issue","key":%s,"trip":%s}`, hb, full(r.ck.Tip()))),
		"owner trip, unknown op":   forge(kernel.TTripOwner, fmt.Sprintf(`{"op":"pause","key":%s,"trip":%s}`, hb, full(honey.Tip()))),
		"owner trip, extra field":  forge(kernel.TTripOwner, fmt.Sprintf(`{"op":"issue","key":%s,"trip":%s,"x":1}`, hb, full(honey.Tip()))),
	} {
		re, err := kernel.Replay(r.anchors(), es)
		must(t, err)
		if len(re.Trips()) != 0 || re.Tripped() || len(re.Changes.Paused) != 0 {
			t.Fatalf("%s folded a trip", name)
		}
		var d *kernel.Divergence
		if _, err := kernel.Rederive(r.anchors(), r.k.Box(), es); !errors.As(err, &d) {
			t.Fatalf("%s: rederive %v", name, err)
		}
	}
	derived := forge(kernel.TTripOwner, fmt.Sprintf(`{"op":"issue","key":%s,"trip":%s}`, hb, full(honey.Tip())))
	re, err := kernel.Replay(r.anchors(), derived)
	must(t, err)
	if !re.Tripped() {
		t.Fatal("the derived owner trip did not fold")
	}
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), derived); err != nil {
		t.Fatalf("the derived owner trip: rederive %v", err)
	}
}

// honeyEntry is the table index of the honey key.
func honeyEntry(t *testing.T, tb decoy.Table) int {
	for i, e := range tb.Entries() {
		if e.Kind == decoy.KHoneyKey {
			return i
		}
	}
	t.Fatal("no honey key")
	return -1
}

// Every security text fits one SMS segment (CH-12).
func TestSecurityTextsFitOneSegment(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	must(t, r.k.OpenTask(0, "t1"))
	r.plan("s", r.serve("t1"), st(key.Trash, entry(t, tb, decoy.PSandboxEnv).Value))
	must(t, r.k.CallTrip(1, kernel.ExitEgress, decoy.Metadata))
	r.plan("f", r.ck, st(key.Trash, entry(t, tb, decoy.PHostEnv).Value))
	texts := r.k.State().SecurityTexts()
	if len(texts) != 3 {
		t.Fatalf("%d texts, want one of each response", len(texts))
	}
	for _, tx := range texts {
		if len(tx.Text) > 160 {
			t.Fatalf("%d characters: %q", len(tx.Text), tx.Text)
		}
	}
}

// An owner's pause of a trip-paused key, made after the trip, outlives the
// trip's resume (KEY-6). Catches the passkey lifting a pause the owner set.
func TestOwnerPauseAfterTripOutlivesResume(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	r.plan("p1", r.ck, st(key.Trash, entry(t, tb, decoy.PHostEnv).Value))
	root := r.trips(1, 1).Scopes[0]
	must(t, r.k.Pause(1, root))
	n, last, _ := r.k.State().TripResume()
	must(t, r.k.ResumeTrip(2, key.Approve(r.owner.pass, kernel.TripResumeHash(n, last))))
	if !r.k.State().Changes.Paused[root] {
		t.Fatal("the resume lifted the owner's own pause")
	}
	r.replays()
}
