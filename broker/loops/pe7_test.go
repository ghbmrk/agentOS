package loops

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: LOOP-1

type counts map[string]int

func (c counts) KeptPairs(cand change.Candidate) int { return c[string(cand.Files["k"])] }

// PE7 (condition 19): among hypotheses with a kept candidate, the one
// whose candidate has the most kept pairs is offered first; the rest keep
// their mined order behind them.
func TestFinishTheCandidateWithTheMostPairsFirst(t *testing.T) {
	hyps := []Hypothesis{{Key: "a"}, {Key: "b"}, {Key: "c"}, {Key: "d"}}
	built := map[string]keptCandidate{
		"b": {cand: change.Candidate{Files: change.Tree{"k": []byte("b")}}},
		"c": {cand: change.Candidate{Files: change.Tree{"k": []byte("c")}}},
		"d": {cand: change.Candidate{Files: change.Tree{"k": []byte("d")}}},
	}
	got := finishFirst(hyps, built, counts{"b": 3, "c": 9})
	var keys []string
	for _, h := range got {
		keys = append(keys, h.Key)
	}
	if strings.Join(keys, "") != "cbad" {
		t.Fatalf("order %v, want c b a d", keys)
	}
}

// PE7 (condition 17): Loop 1 reuses a kept candidate for its config's
// ResumeFor, 36 h in sleep mode, and change.ResumeFor by default.
func TestLearnResumeForFollowsConfig(t *testing.T) {
	if (&Learn{}).resumeFor() != change.ResumeFor {
		t.Fatal("default")
	}
	if (&Learn{cfg: LearnConfig{ResumeFor: 36 * time.Hour}}).resumeFor() != 36*time.Hour {
		t.Fatal("configured")
	}
	if (&Guard{}).resumeFor() != change.ResumeFor || (&Guard{cfg: GuardConfig{ResumeFor: time.Hour}}).resumeFor() != time.Hour {
		t.Fatal("guard")
	}
}
