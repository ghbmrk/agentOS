package call_test

// REQ: CH-5

import (
	"testing"
	"testing/synctest"
	"time"
)

// The ending notice waits for the sentence playing to end (#5304): due
// mid-sentence, it plays once that sentence ends and before the next, which
// never plays; and a 0 while it waits stops the sentence and lets the
// notice play at once. A sentence still playing at EndingWait is cut
// (TestTheOwnerHearsTheEndBeforeMaxCall), and the notice still never
// outlasts MaxCall (the same test, at 10 min).
func TestTheEndingNoticeWaitsForTheSentence(t *testing.T) {
	played := func(r *rig) string {
		select {
		case s := <-r.l.saying:
			return s
		default:
			return ""
		}
	}
	cut := func(r *rig) bool {
		select {
		case <-r.l.cut:
			return true
		default:
			return false
		}
	}

	// Due 1 s into a 3 s sentence: the notice plays 2 s later. It runs ten
	// times: the next sentence is ready when the first ends, so a turn that
	// let a select choose between it and the notice would play it in some
	// run.
	for range 10 {
		synctest.Test(t, func(t *testing.T) {
			r := newRig(t, fixed("One. Two."))
			r.bubble = true
			r.cfg.Clips.Ending = []byte("CLIP:ending")
			r.l.sayFor = 3 * time.Second
			ends := r.records()
			r.serve()
			time.Sleep(29*time.Minute - time.Second)
			r.say("q")
			synctest.Wait()
			if got := played(r); got != "S:One." {
				t.Fatalf("the answer played %q", got)
			}
			time.Sleep(3*time.Second - time.Nanosecond) // the notice fell due at 1 s
			synctest.Wait()
			if got := played(r); got != "" || cut(r) {
				t.Fatalf("mid-sentence: played %q, cut %v", got, cut(r))
			}
			time.Sleep(time.Nanosecond) // the sentence ends
			synctest.Wait()
			if got := played(r); got != "CLIP:ending" {
				t.Fatalf("as the sentence ended: played %q", got)
			}
			time.Sleep(30 * time.Second)
			synctest.Wait()
			if got := played(r); got != "" {
				t.Fatalf("after the notice: played %q", got)
			}
			tu := <-ends
			if !tu.Stopped || tu.Sentences != 1 || cut(r) {
				t.Fatalf("turn = %+v, cut %v", tu, cut(r))
			}
			r.hangup()
			if got := r.l.spoken(); len(got) != 2 || got[0] != "S:One." || got[1] != "CLIP:ending" {
				t.Fatalf("played in full %q", got)
			}
		})
	}

	// A 0 while the notice waits stops the sentence, and the notice plays
	// then, not at EndingWait.
	synctest.Test(t, func(t *testing.T) {
		r := newRig(t, fixed("One."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.l.setGate(true) // the sentence never ends
		r.serve()
		r.say("q")
		synctest.Wait()
		<-r.l.saying
		time.Sleep(29*time.Minute + time.Second)
		synctest.Wait()
		if got := played(r); got != "" {
			t.Fatalf("while the notice waits: played %q", got)
		}
		r.l.keys <- '0'
		synctest.Wait()
		if got := played(r); got != "CLIP:ending" || !cut(r) {
			t.Fatalf("after 0: played %q, cut %v", got, cut(r))
		}
		r.hangup()
	})
}
