package keptmore

import (
	"strings"
	"testing"
)

// REQ: CH-20m
func TestCH20mMORERefusesRedirected(t *testing.T) {
	s := &Store{}
	s.Put(Reply{ID: "K1", Text: "secret private reply body", Redirected: true})
	got, err := s.More("K1")
	if err != nil || got != Refused {
		t.Fatalf("got %q %v", got, err)
	}
}

// REQ: CH-20m
func TestCH20mMOREPagesNonRedirected(t *testing.T) {
	s := &Store{}
	long := strings.Repeat("abcdefghij", 40) // 400 chars
	s.Put(Reply{ID: "K2", Text: long, Redirected: false})
	part1, err := s.More("K2")
	if err != nil || len(part1) == 0 || len(part1) > SMSSegment {
		t.Fatalf("part1 %q (%d) %v", part1, len(part1), err)
	}
	part2, err := s.More("K2")
	if err != nil || part2 == "" || part2 == part1 {
		t.Fatalf("part2 %q %v", part2, err)
	}
	// Exhaust
	for {
		p, err := s.More("K2")
		if err != nil {
			t.Fatal(err)
		}
		if p == Empty {
			break
		}
	}
}

// REQ: CH-20m
func TestCH20mUnknownID(t *testing.T) {
	s := &Store{}
	if _, err := s.More("ZX"); err == nil {
		t.Fatal("expected error")
	}
}
