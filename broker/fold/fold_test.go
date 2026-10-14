// REQ: ARC-6

package fold

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSmallResultsPassThrough(t *testing.T) {
	s := &Store{}
	in := strings.Repeat("a", Max)
	if got := s.Hand("m", in); got != in {
		t.Fatalf("changed a result that fits: %d", len(got))
	}
	if _, ok := s.Read("m", "nope"); ok {
		t.Fatal("stored a result that fits")
	}
}

func TestOversizeIsExactOnReadAndHiddenFromAnotherMachine(t *testing.T) {
	s := &Store{}
	body := strings.Repeat("α", Max) // more bytes than Max
	got := s.Hand("m1", body)
	if got == body || !strings.Contains(got, `"folded":true`) {
		t.Fatalf("not folded: %d bytes", len(got))
	}
	var in StandIn
	if err := json.Unmarshal([]byte(got), &in); err != nil || !in.Folded || in.Bytes != len(body) {
		t.Fatal(err, in)
	}
	if !strings.HasPrefix(body, in.Head) || len(in.Head) > Head {
		t.Fatalf("head %q", in.Head)
	}
	full, ok := s.Read("m1", in.ID)
	if !ok || full != body {
		t.Fatalf("read back %d %v", len(full), ok)
	}
	if _, ok := s.Read("m2", in.ID); ok {
		t.Fatal("another machine read it")
	}
}

func TestTheOldestResultIsDropped(t *testing.T) {
	s := &Store{}
	body := strings.Repeat("b", Max+1)
	var first string
	for i := 0; i < perMachine+1; i++ {
		got := s.Hand("m", body)
		var in StandIn
		if err := json.Unmarshal([]byte(got), &in); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = in.ID
		}
	}
	if _, ok := s.Read("m", first); ok {
		t.Fatal("oldest result was kept")
	}
}

func standIn(t *testing.T, got string) StandIn {
	t.Helper()
	var in StandIn
	if err := json.Unmarshal([]byte(got), &in); err != nil || !in.Folded {
		t.Fatalf("not a stand-in: %.80q %v", got, err)
	}
	return in
}

// One machine going over its count cap drops only its own oldest result.
func TestACapOnlyEvictsTheCallersOwnResults(t *testing.T) {
	s := &Store{}
	body := strings.Repeat("b", Max+1)
	victim := standIn(t, s.Hand("victim", body)).ID
	var first string
	for i := 0; i < perMachine+1; i++ {
		id := standIn(t, s.Hand("attacker", body)).ID
		if i == 0 {
			first = id
		}
	}
	if _, ok := s.Read("victim", victim); !ok {
		t.Fatal("another machine's results evicted the victim's")
	}
	if _, ok := s.Read("attacker", first); ok {
		t.Fatal("attacker kept more than its cap")
	}
}

// The byte bound is per machine too.
func TestTheByteBoundOnlyEvictsTheCallersOwnResults(t *testing.T) {
	s := &Store{}
	victim := standIn(t, s.Hand("victim", strings.Repeat("v", Max+1))).ID
	big := strings.Repeat("a", machineBytes/2)
	for i := 0; i < 3; i++ {
		standIn(t, s.Hand("attacker", big))
	}
	if _, ok := s.Read("victim", victim); !ok {
		t.Fatal("another machine's bytes evicted the victim's result")
	}
}

// A result too large to hold is handed back whole, never as a stand-in that
// cannot be read, and holding nothing evicts nothing.
func TestAResultTooLargeToHoldIsHandedBackWhole(t *testing.T) {
	s := &Store{}
	kept := standIn(t, s.Hand("m", strings.Repeat("k", Max+1))).ID
	body := strings.Repeat("x", machineBytes+1)
	if got := s.Hand("m", body); got != body {
		t.Fatalf("folded a result it cannot hold: %d bytes", len(got))
	}
	if _, ok := s.Read("m", kept); !ok {
		t.Fatal("an unheld result evicted a held one")
	}
}

// When the store as a whole is full, a new result is handed back whole
// rather than evicting another machine's.
func TestAFullStoreHandsBackWholeRatherThanEvictOthers(t *testing.T) {
	s := &Store{}
	big := strings.Repeat("a", machineBytes)
	var ids []string
	for i := 0; i < totalBytes/machineBytes; i++ {
		ids = append(ids, standIn(t, s.Hand(string(rune('A'+i)), big)).ID)
	}
	body := strings.Repeat("n", Max+1)
	if got := s.Hand("newcomer", body); got != body {
		t.Fatal("folded into a full store")
	}
	for i, id := range ids {
		if _, ok := s.Read(string(rune('A'+i)), id); !ok {
			t.Fatalf("machine %d lost its result", i)
		}
	}
}

// Drop forgets every result held for a machine.
func TestDropForgetsAMachinesResults(t *testing.T) {
	s := &Store{}
	body := strings.Repeat("d", Max+1)
	id := standIn(t, s.Hand("m", body)).ID
	other := standIn(t, s.Hand("o", body)).ID
	s.Drop("m")
	if _, ok := s.Read("m", id); ok {
		t.Fatal("dropped machine's result still readable")
	}
	if _, ok := s.Read("o", other); !ok {
		t.Fatal("drop touched another machine")
	}
}
