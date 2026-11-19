package kernel

// REQ: KRN-12, KRN-6, KEY-4, CH-15

// Gaps in trip.go's tests that mutation testing found (#6258): each test
// here fails when one statement or condition of trip.go is deleted or
// negated. They run on a bare State or Kernel, so they reach little else.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/ghbmrk/agentos/broker/decoy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// tgTable is a synthetic decoy table from seed, over a synthetic range.
func tgTable(t *testing.T, seed byte) decoy.Table {
	t.Helper()
	dests := []netip.Addr{netip.MustParseAddr("192.168.77.200"), netip.MustParseAddr("192.168.77.201")}
	tb, err := decoy.Generate(rand.NewChaCha8([32]byte{seed}), dests)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

// tgTableEntry is the logged entry of tb at seq.
func tgTableEntry(tb decoy.Table, seq uint64) Entry {
	return Entry{Seq: seq, Type: TDecoyTable, V: decoy.EventVersion, Body: decoy.Event(tb)}
}

// tgState is a bare state with tb logged.
func tgState(t *testing.T, tb decoy.Table) *State {
	t.Helper()
	s := NewState(nil)
	if err := s.Apply(tgTableEntry(tb, 1)); err != nil {
		t.Fatal(err)
	}
	return s
}

// A honey key needs its whole seed: a short reader is an error, never a
// key from a zero seed every box would share.
func TestHoneyKeyShortReader(t *testing.T) {
	for _, n := range []int{0, ed25519.SeedSize, ed25519.SeedSize + 3} {
		if v, err := HoneyKey(bytes.NewReader(make([]byte, n))); err == nil || v != "" {
			t.Fatalf("%d bytes of seed: %q, %v", n, v, err)
		}
	}
	if _, err := HoneyKey(bytes.NewReader(make([]byte, ed25519.SeedSize+4))); err != nil {
		t.Fatal(err)
	}
}

// With no table logged: an empty table is refused, a call trip has no
// decoy to name, no pause is in force, and a resume says so rather than
// checking a signature.
func TestNoTableLogged(t *testing.T) {
	k := &Kernel{s: NewState(nil)}
	if err := k.LogDecoyTable(0, decoy.Table{}); !errors.Is(err, decoy.ErrBadTable) {
		t.Fatalf("an empty table: %v", err)
	}
	if err := k.CallTrip(0, ExitEgress, netip.MustParseAddr("192.168.77.200")); !errors.Is(err, ErrNoDecoy) {
		t.Fatalf("a call trip with no table: %v", err)
	}
	if n, last, ok := k.s.TripResume(); ok || n != 0 || last != 0 {
		t.Fatalf("no trip, yet resume %d over %d is owed", n, last)
	}
	if err := k.ResumeTrip(0, key.Cosign{}); err == nil || errors.Is(err, ErrTripSig) {
		t.Fatalf("a resume with no pause: %v", err)
	}
}

// A repeat of a session trip's text is held only strictly within
// TextWindow of the one texted (CH-15).
func TestSecurityTextWindowEdge(t *testing.T) {
	s := NewState(nil)
	at := int64(5 * TextWindow)
	for i, d := range []int64{0, TextWindow - 1, TextWindow, 2*TextWindow - 1} {
		s.decoys.log = append(s.decoys.log, Trip{Response: RespSession, Seq: uint64(i + 1), At: at + d})
	}
	got := s.SecurityTexts()
	if len(got) != 2 || got[0].Trip != 1 || got[1].Trip != 3 {
		t.Fatalf("texts %+v, want trips 1 and 3", got)
	}
}

// A plan naming two table destinations trips on the argument first by
// name, whatever order the map gives (KRN-6: the decide and every replay
// derive the same trip).
func TestPlanDestinationTripIsByArgName(t *testing.T) {
	tb := tgTable(t, 7)
	s := tgState(t, tb)
	m := (*s.decoys.table).m
	var first, other netip.Addr
	var firstID, otherID int
	for _, e := range tb.Entries() {
		if e.Dest == decoy.Metadata || !e.Dest.IsValid() {
			continue
		}
		id, ok := m.Dest(e.Dest)
		if !ok {
			continue
		}
		if !first.IsValid() {
			first, firstID = e.Dest, id
		} else if id != firstID {
			other, otherID = e.Dest, id
			break
		}
	}
	if !other.IsValid() {
		t.Fatal("the table has no two destinations")
	}
	args := map[string]string{"a": first.String()}
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"} {
		args[n] = other.String()
	}
	p := Plan{ID: "p", Steps: []PlanStep{{Verb: key.Trash, Clerk: "c", Args: args}}}
	for i := 0; i < 64; i++ {
		tr := s.tripOf(p)
		if tr == nil || tr.Cause != CauseDest || tr.Entry != firstID {
			t.Fatalf("run %d: trip %+v, want destination entry %d (not %d)", i, tr, firstID, otherID)
		}
	}
}

// tripOK accepts each response only in its own shape: a session or full
// trip only in its own plan's rejection, a call trip only as an input.
func TestTripShapes(t *testing.T) {
	s := tgState(t, tgTable(t, 7))
	call := Trip{Cause: CauseDest, Exit: ExitEgress, Entry: 0, Response: RespCall}
	sess := Trip{Cause: CauseDest, Exit: ExitKernel, Entry: 0, Response: RespSession, Plan: "p", Session: "t"}
	full := Trip{Cause: CauseValue, Exit: ExitKernel, Entry: 0, Response: RespFull, Plan: "p", Scopes: []key.ID{{1}}}
	with := func(tr Trip, f func(*Trip)) Trip { f(&tr); return tr }
	for _, c := range []struct {
		what     string
		tr       Trip
		rejected string
		ok       bool
	}{
		{"call", call, "", true},
		{"call, unknown cause", with(call, func(t *Trip) { t.Cause = "x" }), "", false},
		{"call, unknown response", with(call, func(t *Trip) { t.Response = "x" }), "", false},
		{"session", sess, "p", true},
		{"session, no plan", with(sess, func(t *Trip) { t.Plan = "" }), "", false},
		{"session, another plan", with(sess, func(t *Trip) { t.Plan = "q" }), "p", false},
		{"session, as an input", sess, "", false},
		{"session, scopes", with(sess, func(t *Trip) { t.Scopes = []key.ID{{1}} }), "p", false},
		{"full", full, "p", true},
		{"full, no plan", with(full, func(t *Trip) { t.Plan = "" }), "", false},
		{"full, another plan", with(full, func(t *Trip) { t.Plan = "q" }), "p", false},
		{"full, as an input", full, "", false},
		{"full, a session", with(full, func(t *Trip) { t.Session = "t" }), "p", false},
	} {
		if got := s.tripOK(c.tr, c.rejected); got != c.ok {
			t.Errorf("%s: tripOK %v, want %v", c.what, got, c.ok)
		}
	}
}

// A full trip with no scope, while planning is already stopped, pauses
// nothing new, so it neither moves what the resume signs nor texts.
func TestScopelessFullTripWhileStopped(t *testing.T) {
	s := NewState(nil)
	s.addTrip(Trip{Response: RespFull}, Entry{Seq: 1, At: 1})
	s.addTrip(Trip{Response: RespFull}, Entry{Seq: 2, At: 2})
	if n, last, ok := s.TripResume(); !ok || n != 0 || last != 1 {
		t.Fatalf("resume %d over %d (%v), want 0 over 1", n, last, ok)
	}
	if tx := s.SecurityTexts(); len(tx) != 1 || tx[0].Trip != 1 {
		t.Fatalf("texts %+v, want trip 1's only", tx)
	}
}

// The table is logged once: a second table entry folds nothing, a corrupt
// one is a corrupt log, and so is any trip entry whose body does not read.
func TestTripEntriesFold(t *testing.T) {
	one, two := tgTable(t, 7), tgTable(t, 8)
	s, err := Replay(nil, []Entry{tgTableEntry(one, 1), tgTableEntry(two, 2)})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal((*s.decoys.table).entries)
	want, _ := json.Marshal(one.Entries())
	if !bytes.Equal(got, want) {
		t.Fatal("a second table entry replaced the first")
	}
	if _, err := Replay(nil, []Entry{{Seq: 1, Type: TDecoyTable, V: decoy.EventVersion, Body: json.RawMessage(`"x"`)}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a corrupt table: %v", err)
	}
	for _, typ := range []string{TTrip, TTripOwner, TTripResumed} {
		if _, err := Replay(nil, []Entry{tgTableEntry(one, 1), {Seq: 2, Type: typ, V: 1, Body: json.RawMessage(`"x"`)}}); err == nil {
			t.Fatalf("a %s entry whose body does not read folded", typ)
		}
	}
}

// A trip stops its session: the task ends, and only that task's active
// plans are cancelled; a pending one of it, and another task's, stand.
func TestStopSessionStopsOnlyItsActivePlans(t *testing.T) {
	issuer := key.Ed25519Signer(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	root := key.Issue(issuer, key.Root{Clerk: "bank", Verbs: []key.Verb{key.Trash}, Serial: "01"})
	pub, _, _ := ed25519.GenerateKey(bytes.NewReader(make([]byte, 64)))
	keyOf := func(task string) key.Key {
		k, err := key.ClerkKey(root, issuer, pub, 0, 1<<20, key.LimitTask(task))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	s := NewState(nil)
	s.tasks["t"] = &taskState{Task: Task{ID: "t", Until: 1 << 40}}
	s.tasks["u"] = &taskState{Task: Task{ID: "u", Until: 1 << 40}}
	add := func(id, task, status string) {
		s.Order = append(s.Order, id)
		s.Plans[id] = &PlanState{Plan: Plan{ID: id, Key: keyOf(task)}, Status: status, Steps: []StepState{{Phase: PQueued}}}
	}
	add("a", "t", SActive)
	add("b", "u", SActive)
	add("c", "t", SPending)
	if s.Plans["a"].Plan.Task() != "t" {
		t.Fatalf("plan a serves %q", s.Plans["a"].Plan.Task())
	}
	s.stopSession("t")
	if _, ok := s.Task("t", 0); ok {
		t.Fatal("the stopped session's task is live")
	}
	if _, ok := s.Task("u", 0); !ok {
		t.Fatal("another task ended")
	}
	for id, want := range map[string]string{"a": SCancelled, "b": SActive, "c": SPending} {
		if p := s.Plans[id]; p.Status != want {
			t.Errorf("plan %s is %s, want %s", id, p.Status, want)
		}
	}
	if p := s.Plans["a"]; p.Cancel != CTrip {
		t.Errorf("plan a cancelled for %q", p.Cancel)
	}
}
