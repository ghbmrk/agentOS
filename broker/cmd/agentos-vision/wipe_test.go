package main

// REQ: DEV-7

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A template the service will not send is zeroed: one its own check
// refuses, and one a timed-out call returns late, after the reload (DEV-7;
// the two wipe calls in call).
func TestUnsentTemplatesAreZeroed(t *testing.T) {
	log := &lockedBuffer{}
	s := newService(Config{CallTimeout: 20 * time.Millisecond}, newFake(), log)
	s.stuck = func() { t.Error("the late call was taken for stuck") }
	refused := []byte{1, 2, 3, 4}
	_, err := call(s, s.cur, func() {}, func() ([]byte, error) { return refused, nil },
		func([]byte) error { return errors.New("outside the protocol") })
	if err != errMalformed {
		t.Fatalf("a refused template: %v", err)
	}
	if !zero(refused) {
		t.Fatal("a template the check refused was not zeroed")
	}
	late := []byte{5, 6, 7, 8}
	gate := make(chan struct{})
	_, err = call(s, s.cur, func() {}, func() ([]byte, error) { <-gate; return late, nil },
		func([]byte) error { return nil })
	if err != errTimedOut {
		t.Fatalf("a slow call: %v", err)
	}
	close(gate)
	// The log line comes after the wipe, so seeing it orders the read.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(log.String(), "late runtime answer was discarded") {
		if time.Now().After(deadline) {
			t.Fatal("the late answer was never discarded")
		}
		time.Sleep(time.Millisecond)
	}
	if !zero(late) {
		t.Fatal("a template returned after its timeout was not zeroed")
	}
}

func zero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
