package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
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

// PE2 (UX-114-1, potency C1 on #114): with replay disabled for lack of
// memory, the owner sees learning is off in effect: STATUS says so after
// the clock note, and turning learning or all loops back on says nothing
// new will be adopted, keeping the "if this wasn't you" line (security C1
// on #49). With room, neither appears.
func TestPE2NoRoomForReplayIsSaid(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	cfg.Notes = []func() string{func() string { return "clock note" }}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel() }()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	lp.attach(ctx, d)
	notes := func() (out []string) {
		for _, n := range cfg.Notes {
			if s := n(); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	if got := notes(); len(got) != 1 {
		t.Fatalf("notes with room: %q", got)
	}
	if got, ok := cfg.Settings(ctx, "LEARNING ON", true); !ok || strings.Contains(got, "memory") {
		t.Fatalf("LEARNING ON with room: %q", got)
	}

	lp.noRoom.Store(true)
	if got := notes(); len(got) != 2 || got[0] != "clock note" || got[1] != noRoomNote {
		t.Fatalf("notes without room: %q", got)
	}
	if noRoomNote != "Learning: paused, the box's memory is too small to test changes." {
		t.Fatalf("note %q", noRoomNote)
	}
	for msg, want := range map[string]string{
		"LEARNING ON": "Learning is on, but the box's memory is too small to test changes, so nothing new will be adopted. Reply LEARNING OFF if this wasn't you.",
		"LOOPS ON":    "Spare-time work is back on. Learning is on, but the box's memory is too small to test changes, so nothing new will be adopted. Reply LOOPS OFF if this wasn't you.",
	} {
		if got, ok := cfg.Settings(ctx, msg, true); !ok || got != want {
			t.Errorf("%s: %q", msg, got)
		}
	}
	// Other settings are unchanged.
	if got, ok := cfg.Settings(ctx, "SECURITY TESTS ON", true); !ok || strings.Contains(got, "memory") {
		t.Errorf("SECURITY TESTS ON: %q", got)
	}
	if got, ok := cfg.Settings(ctx, "LEARNING OFF", true); !ok || strings.Contains(got, "memory") {
		t.Errorf("LEARNING OFF: %q", got)
	}
	cancel()
	d.Wait()
}

// PE6 (R1 on #114): unless -capacity-mb is given, admission's capacity is
// this box's memory less the rest of the RES-2 floor budget (host,
// inference, browser), at most the 4500 MB default, so the N95 (pool
// about 3496 MB) is not over-committed. The figure and its source are
// logged; an unreadable MemTotal keeps the default and says so.
func TestPE6CapacityFollowsTheBoxMemory(t *testing.T) {
	const n95 = "MemTotal:        7864320 kB\nMemAvailable:    7340032 kB\n"
	for _, c := range []struct {
		name     string
		meminfo  string
		explicit bool
		flag     int64
		want     int64
		says     string
	}{
		{"n95", n95, false, defaultCapacityMB, 4096, "MemTotal 7680 MB"},
		{"large box", "MemTotal: 16777216 kB\n", false, defaultCapacityMB, 4500, "at most 4500"},
		{"unreadable", "", false, defaultCapacityMB, 4500, "MemTotal unreadable"},
		{"explicit", n95, true, 5000, 5000, "-capacity-mb"},
	} {
		got, why := capacityFor(c.meminfo, c.explicit, c.flag)
		if got != c.want || !strings.Contains(why, c.says) {
			t.Errorf("%s: %d MB (%q), want %d MB naming %q", c.name, got, why, c.want, c.says)
		}
	}
	// On the N95 the defaults still hold the agent and one replay machine.
	n, _ := capacityFor(n95, false, defaultCapacityMB)
	if err := replayFits(n, defaultHeadroomMB, defaultAgentMemMB, defaultReplayMemMB); err != nil {
		t.Fatalf("N95: %v", err)
	}
}
