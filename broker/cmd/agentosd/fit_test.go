package main

import (
	"strings"
	"testing"
)

// REQ: RES-2, LOOP-5

// PE2: the agent machine and one replay machine must fit in the pool
// admission hands out (capacity less headroom) at the same time, or every
// evaluation is refused or preempted while the agent runs and learning
// stalls without a word. The defaults fit; a replay budget that does not
// is refused at start with the figures named.
func TestPE2AgentAndOneReplayMachineFit(t *testing.T) {
	if err := replayFits(defaultCapacityMB, defaultHeadroomMB, defaultAgentMemMB, defaultReplayMemMB); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if defaultReplayMemMB >= defaultAgentMemMB {
		t.Fatalf("replay budget %d MB is not set apart from the agent's %d MB", defaultReplayMemMB, defaultAgentMemMB)
	}
	err := replayFits(4500, 600, 1536, 2400)
	if err == nil {
		t.Fatal("agent 1536 + replay 2400 admitted into a 3900 MB pool")
	}
	for _, want := range []string{"1536", "2400", "3900"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	if replayFits(4500, 600, 1536, 2364) != nil {
		t.Error("an exact fit is refused")
	}
	if replayFits(4500, 600, 1536, 0) == nil {
		t.Error("a zero replay budget is accepted")
	}
}
