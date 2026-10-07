package owner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: CH-2
func TestLocalStopBypassesHeldOwnerStateLock(t *testing.T) {
	r := newRig(t, nil)
	r.ch.mu.Lock()
	defer r.ch.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- r.ch.LocalStop(context.Background()) }()
	select {
	case err := <-done:
		if err != nil || !r.eng.Stopped() {
			t.Fatal("local containment failed", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("local STOP waited behind owner-state work")
	}
}
func TestLocalStopInvalidatesEarlierResumeGeneration(t *testing.T) {
	r := newRig(t, nil)
	gen := r.ch.stops.Load()
	if err := r.ch.LocalStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.resumeUnlessStopped(gen); !errors.Is(err, errStoppedMeanwhile) {
		t.Fatal("old RESUME survived local STOP", err)
	}
	if !r.eng.Stopped() {
		t.Fatal("local STOP lifted")
	}
}
func TestLocalStopDuringTextResumeVerifierIsNotLifted(t *testing.T) {
	for _, challenge := range []bool{false, true} {
		t.Run(map[bool]string{false: "resume-code", true: "challenge"}[challenge], func(t *testing.T) {
			r, f := newVerifierRig(t)
			r.ch.codes.st.LowLocked = true
			r.say("STOP")
			resume := "RESUME "
			if challenge {
				r.ch.codes.st.Challenged = true
				m := tokenRe.FindStringSubmatch(r.say("UNLOCK"))
				if len(m) < 2 {
					t.Fatal("no challenge")
				}
				resume = "RESUME " + m[1] + " "
			} else {
				r.say("RESUME")
			}
			block := make(chan error, 1)
			f.mu.Lock()
			f.block = block
			f.mu.Unlock()
			defer func() {
				select {
				case block <- nil:
				default:
				}
			}()
			before := f.calls()
			done := make(chan string, 1)
			code := r.totp()
			go func() { done <- strings.Join(r.ch.Handle(context.Background(), ownerNum, resume+code), " | ") }()
			deadline := time.Now().Add(time.Second)
			for f.calls() == before {
				if time.Now().After(deadline) {
					t.Fatal("no verifier call")
				}
				time.Sleep(time.Millisecond)
			}
			stopped := make(chan error, 1)
			go func() { stopped <- r.ch.LocalStop(context.Background()) }()
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(200 * time.Millisecond):
				t.Fatal("local STOP blocked behind verifier")
			}
			block <- nil
			select {
			case text := <-done:
				if !strings.Contains(text, "A STOP arrived while the code was checked") || !r.eng.Stopped() {
					t.Fatal("earlier RESUME lifted local containment", text)
				}
			case <-time.After(time.Second):
				t.Fatal("resume did not complete")
			}
		})
	}
}
