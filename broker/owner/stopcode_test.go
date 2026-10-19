package owner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// REQ: CH-2

// TestStopWithACodeStopsAndVoidsAnEarlierResumeCode: a STOP sent with a
// code (CH-14) is STOP, locked or unlocked and whether the code is right
// or wrong, and in challenge mode (O4). It counts in the STOP generation, so a RESUME code issued
// before it no longer lifts it, and the code is never checked, counted or
// passed on (SEC-stop-with-code, #2459).
func TestStopWithACodeStopsAndVoidsAnEarlierResumeCode(t *testing.T) {
	for _, mode := range []string{"locked", "unlocked", "challenged"} {
		for _, right := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s right=%v", mode, right), func(t *testing.T) {
				r := newRig(t, nil)
				if mode == "unlocked" {
					r.unlock()
				}
				bare := r.say("STOP")
				resume := regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
				code := r.totp()
				if !right {
					n, _ := strconv.Atoi(code)
					code = fmt.Sprintf("%06d", (n+1)%1000000)
				}
				r.ch.codes.st.Challenged = mode == "challenged" // after the RESUME code, which challenge mode would withhold
				r.eng.mu.Lock()
				r.eng.stopped = false // running again, so this STOP has work to do
				r.eng.mu.Unlock()
				gen, sent := r.ch.stops.Load(), len(r.agent.got())
				wrong, until := len(r.ch.codes.st.Wrong), r.ch.codes.st.UnlockedUntil
				if got := r.say("STOP " + code); got != bare || !r.eng.Stopped() {
					t.Fatalf("STOP with a code: %q (bare STOP: %q), stopped %v", got, bare, r.eng.Stopped())
				}
				if r.ch.stops.Load() != gen+1 {
					t.Fatal("STOP with a code was not counted")
				}
				if len(r.agent.got()) != sent || len(r.ch.codes.st.Wrong) != wrong || !r.ch.codes.st.UnlockedUntil.Equal(until) {
					t.Fatalf("the code was checked or passed on: agent %v, wrong %d, unlocked until %v",
						r.agent.got(), len(r.ch.codes.st.Wrong), r.ch.codes.st.UnlockedUntil)
				}
				r.ch.codes.st.Challenged = false // so the RESUME below meets the STOP generation, not the challenge drop
				if got := r.say("RESUME " + resume); !strings.HasPrefix(got, "No valid code") || !r.eng.Stopped() {
					t.Fatalf("a RESUME code from before the STOP lifted it: %q", got)
				}
			})
		}
	}
}
