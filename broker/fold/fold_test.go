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
