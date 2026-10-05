package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/loopbuild"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: LOOP-2, OP-8, REV-5

// W3-builder (C-3c-2): a builder machine reaches only the builder's
// socket, never the live plane where managed_tree and executors are; with
// no builder it cannot start.
func TestBuilderMachinesReachOnlyTheBuilder(t *testing.T) {
	live, build := &recServices{}, &recServices{}
	var s lateServices
	s.live.Store(&svc{live})
	if _, err := s.Open(loopbuild.Prefix + "0a1b"); err == nil || len(live.opened) != 0 {
		t.Fatal("a builder machine started with no builder, or reached the live plane")
	}
	s.build.Store(&svc{build})
	for _, id := range []string{"agent", loopbuild.Prefix + "0a1b"} {
		if _, err := s.Open(id); err != nil {
			t.Fatal(err)
		}
	}
	if len(live.opened) != 1 || len(build.opened) != 1 || build.opened[0] != loopbuild.Prefix+"0a1b" {
		t.Fatalf("live %q, builder %q", live.opened, build.opened)
	}
	if loopbuild.Prefix != modelroute.BuilderPrefix {
		t.Fatal("the builder's prefix is not the vault process's")
	}
}

// Loop 1's model-backed builder serves every signal but repeats, offers no
// job until the box attaches one (no image, no machines: Ready false), and
// its candidates are never public (C-3c-4). Its machines' model calls have
// their own share of the spare budget, beside evaluation's (C-3c-5).
func TestLoop1sModelBuilderWaitsForTheBox(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{JournalPath: filepath.Join(dir, "journal.log")}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []loops.Signal{loops.SignalFailure, loops.SignalCorrection, loops.SignalSlow, loops.SignalExpensive} {
		br := loops.Brief{Hypothesis: loops.Hypothesis{Signal: s, Class: change.ClassProcedure}}
		if !lp.builder.Handles(s) || lp.builder.Ready(br) || !lp.builder.Private(br) {
			t.Fatalf("%s: handles %v, ready %v, private %v", s, lp.builder.Handles(s), lp.builder.Ready(br), lp.builder.Private(br))
		}
		if _, err := lp.builder.Build(context.Background(), br); err == nil {
			t.Fatalf("%s built with no builder attached", s)
		}
	}
	if lp.builder.Private(loops.Brief{Hypothesis: loops.Hypothesis{Signal: loops.SignalRepeat}}) {
		t.Fatal("the in-process compiler's skills are marked private by the builder")
	}
	if sh := builderShare(); sh.Prefix != loopbuild.Prefix || sh.Reserve != 0 || sh.Max < 0.3 || sh.Max > 0.4 {
		t.Fatalf("builder share %+v", sh)
	}
}

// Security R2 on #126 (C-3c-3): the builder never runs the agent's image,
// by name or by the same directory under another name.
func TestTheBuilderNeverRunsTheAgentImage(t *testing.T) {
	imgs := images{"openclaw": "/img/openclaw", "alias": "/img/openclaw"}
	var l learning
	var s lateServices
	for _, name := range []string{"openclaw", "alias"} {
		if err := l.openBuilder(nil, imgs, &s, buildConfig{Image: name, AgentImage: "openclaw"}); err == nil {
			t.Fatalf("builder image %q, the agent's, was accepted", name)
		}
	}
	if s.build.Load() != nil {
		t.Fatal("a builder was attached")
	}
}
