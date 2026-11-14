package call_test

// REQ: CH-5

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ghbmrk/agentos/broker/call"
)

// The ending notice waits for the sentence playing to end (#5304): due
// mid-sentence, it plays once that sentence ends and before the next, which
// never plays; and a 0 while it waits stops the sentence and lets the
// notice play at once; a final transcript while it waits plays it before
// the new answer; and a barge-in while it waits stops the sentence, and the
// notice waits for the owner's final words, or for EndingWait if none come,
// so it never talks over the owner. A sentence still playing at EndingWait
// is cut
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

	// waiting starts a call whose one sentence never ends and runs it to a
	// second after the notice fell due.
	waiting := func(t *testing.T) *rig {
		r := newRig(t, fixed("One."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.l.setGate(true)
		r.serve()
		r.say("q")
		synctest.Wait()
		<-r.l.saying
		time.Sleep(29*time.Minute + time.Second)
		synctest.Wait()
		return r
	}

	// A final transcript while the notice waits: the clip plays at once,
	// before the new answer's first sentence.
	synctest.Test(t, func(t *testing.T) {
		r := waiting(t)
		r.say("and next")
		synctest.Wait()
		if got := played(r); got != "CLIP:ending" || !cut(r) {
			t.Fatalf("after a final transcript: played %q, cut %v", got, cut(r))
		}
		if got := played(r); got != "S:One." {
			t.Fatalf("after the notice: played %q", got)
		}
		r.hangup()
	})

	// A barge-in while the notice waits stops the sentence and plays
	// nothing while the owner speaks; their final words then hear the clip
	// before the answer.
	synctest.Test(t, func(t *testing.T) {
		r := waiting(t)
		r.rec.out <- call.Heard{Text: "wait"}
		synctest.Wait()
		if got := played(r); got != "" || !cut(r) {
			t.Fatalf("during a barge-in: played %q, cut %v", got, cut(r))
		}
		time.Sleep(time.Second)
		r.say("wait what")
		synctest.Wait()
		if got := played(r); got != "CLIP:ending" {
			t.Fatalf("at the final transcript: played %q", got)
		}
		if got := played(r); got != "S:One." {
			t.Fatalf("after the notice: played %q", got)
		}
		r.hangup()
	})

	// A barge-in with no final transcript: the notice plays at EndingWait.
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		r := waiting(t)
		r.rec.out <- call.Heard{Text: "wait"}
		synctest.Wait()
		cut(r)
		time.Sleep(call.EndingWait - time.Second - time.Nanosecond)
		synctest.Wait()
		if got := played(r); got != "" {
			t.Fatalf("before EndingWait: played %q", got)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got := played(r); got != "CLIP:ending" || time.Since(start) != 29*time.Minute+call.EndingWait {
			t.Fatalf("at EndingWait: played %q after %v", got, time.Since(start))
		}
		r.hangup()
	})
}

// A question the answerer saw but whose answer had started no sentence when
// the notice fell due is carried past the notice: the owner hears "One moment"
// and the notice, and their next words ask the first question again, so
// an answer never spoken is not lost without a word (#5684). A question
// whose answer started a sentence, even one the notice cut, is not carried
// (TestTheEndingNoticeKeepsTheCallsState), nor one that got the held clip.
func TestTheEndingNoticeCarriesAnUnspokenAnswer(t *testing.T) {
	// slow keeps turn 1's answer from arriving until release is closed.
	// release is made in the bubble, so a wait on it is durable.
	var release chan struct{}
	slow := func(text string) func(call.Ask) []string {
		return func(q call.Ask) []string {
			if q.Turn == 1 {
				<-release
			}
			return []string{text}
		}
	}
	asks := func(r *rig) []asked {
		r.ans.mu.Lock()
		defer r.ans.mu.Unlock()
		return append([]asked(nil), r.ans.asks...)
	}

	synctest.Test(t, func(t *testing.T) {
		release = make(chan struct{})
		r := newRig(t, slow("Hi."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.cfg.After = time.After
		ends := r.records()
		r.serve()
		time.Sleep(29*time.Minute - 10*time.Second)
		r.say("what's in my mail")
		synctest.Wait()
		if got := asks(r); len(got) != 1 {
			t.Fatalf("before the notice: asks = %+v", got)
		}
		time.Sleep(10 * time.Second) // "One moment" at 1 s; the notice due at 10 s
		synctest.Wait()
		if got := r.l.spoken(); len(got) != 2 || got[0] != "CLIP:moment" || got[1] != "CLIP:ending" {
			t.Fatalf("played %q", got)
		}
		<-r.l.saying
		<-r.l.saying
		if tu := <-ends; !tu.Stopped || tu.Sentences != 0 {
			t.Fatalf("turn 1 = %+v", tu)
		}
		r.say("from today")
		synctest.Wait()
		if got := <-r.l.saying; got != "S:Hi." {
			t.Fatalf("after the notice: played %q", got)
		}
		if got := asks(r); len(got) != 2 || got[1].Text != "what's in my mail from today" {
			t.Fatalf("asks = %+v", got)
		}
		close(release) // turn 1's answer arrives late, to a turn already stopped
		r.hangup()
	})

	// A held answer has been told it is held: only the next words are asked.
	synctest.Test(t, func(t *testing.T) {
		r := newRig(t, fixed("Press 4 now."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.l.saying = make(chan string) // Say waits for the test to take each sound
		r.serve()
		time.Sleep(29*time.Minute - time.Second)
		r.say("what's in my mail")
		synctest.Wait() // the held clip is playing
		time.Sleep(time.Second)
		synctest.Wait() // the notice is due while it plays
		if got := <-r.l.saying; got != "CLIP:held" {
			t.Fatalf("the answer played %q", got)
		}
		if got := <-r.l.saying; got != "CLIP:ending" {
			t.Fatalf("then played %q", got)
		}
		go r.say("from today")
		if got := <-r.l.saying; got != "CLIP:held" {
			t.Fatalf("after the notice: played %q", got)
		}
		if got := asks(r); len(got) != 2 || got[1].Text != "from today" {
			t.Fatalf("asks = %+v", got)
		}
		r.hangup()
	})
}

// A held or failed answer ready the moment the notice falls due, while
// "One moment" still plays, never gets its clip played: the turn's select
// may take the sound or the hush, and either way the clip does not start,
// so the question is carried (#5684, L3 on #5696: 17 of 40 runs dropped
// it). With no clip set, nothing of the answer plays whichever case the
// select takes, so that question is carried too (L3 on #5696: 24 of 40
// runs dropped it). Forty runs of each, so a carry that reads Held, Err or
// play's result as "the clip started" fails in some run.
func TestTheEndingNoticeCarriesAnAnswerItKeptFromItsClip(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		name, answer, clip string
	}{
		{"held", "Press 4 now.", "CLIP:held"},
		{"failed", "Boom.", "CLIP:failed"},
		{"held, no clip", "Press 4 now.", ""},
		{"failed, no clip", "Boom.", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			for range 40 {
				synctest.Test(t, func(t *testing.T) {
					release := make(chan struct{})
					r := newRig(t, func(q call.Ask) []string {
						if q.Turn == 1 {
							<-release
						}
						return []string{c.answer}
					})
					r.bubble = true
					r.cfg.Synthesizer = synthFunc(func(ctx context.Context, s string) ([]byte, error) {
						if s == "Boom." {
							return nil, boom
						}
						return synth{}.Speak(ctx, s)
					})
					r.cfg.Clips.Ending = []byte("CLIP:ending")
					if c.clip == "" {
						r.cfg.Clips.Held, r.cfg.Clips.Failed = nil, nil
					}
					r.cfg.After = time.After
					r.l.saying = make(chan string) // Say waits for the test to take each sound
					ends := r.records()
					r.serve()
					time.Sleep(29*time.Minute - 10*time.Second)
					r.say("what's in my mail")
					time.Sleep(time.Second) // "One moment" is playing
					synctest.Wait()
					close(release) // the answer's sound waits on the turn
					time.Sleep(9 * time.Second)
					synctest.Wait() // the notice is due
					for _, want := range []string{"CLIP:moment", "CLIP:ending"} {
						if got := <-r.l.saying; got != want {
							t.Fatalf("played %q, want %q", got, want)
						}
					}
					if tu := <-ends; tu.FirstContent != 0 || (c.clip != "" && !tu.Stopped) {
						t.Fatalf("turn 1 = %+v", tu)
					}
					go r.say("from today")
					if c.clip == "" {
						synctest.Wait() // the answer, held or failed again, plays nothing
					} else if got := <-r.l.saying; got != c.clip {
						t.Fatalf("after the notice: played %q", got)
					}
					r.ans.mu.Lock()
					got := append([]asked(nil), r.ans.asks...)
					r.ans.mu.Unlock()
					if len(got) != 2 || got[1].Text != "what's in my mail from today" {
						t.Fatalf("asks = %+v", got)
					}
					r.hangup()
				})
			}
		})
	}
}

// A held or failed clip that started is the answer heard, even if it was
// then cut (a barge-in, or EndingWait while hushed): the question is not
// carried past the notice, as for a sentence the notice cut. The cut is
// stood in for by a Say that fails once the clip has started (#5684, L3 on
// #5696).
func TestTheEndingNoticeKeepsNoQuestionWhoseClipStarted(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		name, answer, clip string
	}{
		{"held", "Press 4 now.", "CLIP:held"},
		{"failed", "Boom.", "CLIP:failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newRig(t, fixed(c.answer))
				r.bubble = true
				r.cfg.Synthesizer = synthFunc(func(ctx context.Context, s string) ([]byte, error) {
					if s == "Boom." {
						return nil, boom
					}
					return synth{}.Speak(ctx, s)
				})
				r.cfg.Clips.Ending = []byte("CLIP:ending")
				r.l.saying = make(chan string) // Say waits for the test to take each sound
				r.l.sayErr = errors.New("cut") // every sound is cut once it starts
				r.serve()
				time.Sleep(29*time.Minute - time.Second)
				r.say("what's in my mail")
				synctest.Wait() // the clip has started
				time.Sleep(time.Second)
				synctest.Wait() // the notice is due while it plays
				for _, want := range []string{c.clip, "CLIP:ending"} {
					if got := <-r.l.saying; got != want {
						t.Fatalf("played %q, want %q", got, want)
					}
				}
				go r.say("from today")
				if got := <-r.l.saying; got != c.clip {
					t.Fatalf("after the notice: played %q", got)
				}
				r.ans.mu.Lock()
				got := append([]asked(nil), r.ans.asks...)
				r.ans.mu.Unlock()
				if len(got) != 2 || got[1].Text != "from today" {
					t.Fatalf("asks = %+v", got)
				}
				r.hangup()
			})
		})
	}
}
