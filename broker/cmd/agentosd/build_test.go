package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/loopbuild"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vm"
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

// UX-126-1: when -builder-image is set and the builder cannot start,
// STATUS says that learning from failed, corrected, slow or costly tasks
// is not running; with no builder attempted, nothing is said.
func TestStatusSaysWhenTheBuilderDidNotStart(t *testing.T) {
	l := testLearning(t)
	if n := l.builderNote(); n != "" {
		t.Fatalf("no builder attempted, note %q", n)
	}
	var s lateServices
	l.startBuilder(nil, images{}, &s, buildConfig{Image: "missing"})
	if n := l.builderNote(); n != builderOffNote {
		t.Fatalf("note %q", n)
	}
	// UX R1 on #126: after LEARNING OFF, a restart would not help.
	if reply, ok := l.sched.Text(context.Background(), "LEARNING OFF", true); !ok || l.learningOn() {
		t.Fatalf("LEARNING OFF: %q", reply)
	}
	if n := l.builderNote(); n != "" {
		t.Fatalf("note with learning off %q", n)
	}
}

// testLearning opens agentosd's learning plane in a temporary directory
// and attaches it to a running daemon.
func testLearning(t *testing.T) *learning {
	t.Helper()
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	lp.attach(ctx, d)
	return lp
}

// fakeBuilderMachines is a vm manager with leftover builder machines and
// no others.
type fakeBuilderMachines struct{ destroyed []string }

func (f *fakeBuilderMachines) Create(context.Context, string, vm.Spec) (vm.Machine, error) {
	return vm.Machine{}, errors.New("not in this test")
}
func (f *fakeBuilderMachines) Get(string) (vm.Machine, error) {
	return vm.Machine{}, errors.New("no such machine")
}
func (f *fakeBuilderMachines) Resume(context.Context, string) error { return nil }
func (f *fakeBuilderMachines) Destroy(_ context.Context, id string) error {
	f.destroyed = append(f.destroyed, id)
	return nil
}
func (f *fakeBuilderMachines) Machines() []string {
	return []string{"agent", loopbuild.Prefix + "left"}
}
func (f *fakeBuilderMachines) DataLabel(string) string { return "private" }

// L3 S1 on #126: openBuilder's happy path attaches the builder to Loop 1
// and to builder machines' services, destroys builder machines a
// previous run left, and leaves no STATUS note.
func TestOpenBuilderAttachesTheBuilder(t *testing.T) {
	lp := testLearning(t)
	dir := t.TempDir()
	f := &fakeBuilderMachines{}
	var s lateServices
	lp.startBuilder(f, images{"builder": "/img/builder", "openclaw": "/img/openclaw"}, &s,
		buildConfig{Dir: filepath.Join(dir, "build"), Image: "builder", AgentImage: "openclaw", Egress: filepath.Join(dir, "egress.sock")})
	if n := lp.builderNote(); n != "" {
		t.Fatalf("note %q", n)
	}
	if s.build.Load() == nil || !lp.build.Ready(loops.Brief{}) {
		t.Fatal("the builder was not attached")
	}
	if len(f.destroyed) != 1 || f.destroyed[0] != loopbuild.Prefix+"left" {
		t.Fatalf("destroyed %v", f.destroyed)
	}
}

// Potency R3 on #126 (BOARD W3-builder-tune): with no -builder-image,
// STATUS says that only repeated routines are learned, so an inert
// builder is never silent; after LEARNING OFF it says nothing.
func TestStatusSaysWhenNoBuilderIsSetUp(t *testing.T) {
	l := testLearning(t)
	var s lateServices
	l.startBuilder(nil, images{}, &s, buildConfig{})
	if n := l.builderNote(); n != builderUnsetNote {
		t.Fatalf("note %q", n)
	}
	if s.build.Load() != nil || l.build.Ready(loops.Brief{}) {
		t.Fatal("a builder was attached with no image")
	}
	if reply, ok := l.sched.Text(context.Background(), "LEARNING OFF", true); !ok || l.learningOn() {
		t.Fatalf("LEARNING OFF: %q", reply)
	}
	if n := l.builderNote(); n != "" {
		t.Fatalf("note with learning off %q", n)
	}
}

// W3-builder-ship: the builder's image name and launch file have defaults
// the box image installs, so its unit need not pass them. Fail-closed: a
// box whose image does not carry the builder (the default name is not
// registered with -image) runs no builder, and STATUS says it learns from
// repeated routines only; a builder image registered without its launch
// file does not start, and STATUS says so.
func TestTheBuilderDefaultsFailClosed(t *testing.T) {
	if defaultBuilderImage != "builder" || defaultBuilderLaunch != "/usr/lib/agentos/builder/launch.json" {
		t.Fatalf("defaults %q %q", defaultBuilderImage, defaultBuilderLaunch)
	}
	l := testLearning(t)
	var s lateServices
	l.startBuilder(nil, images{"openclaw": "/img/openclaw"}, &s, buildConfig{Image: defaultBuilderImage, ImageDefault: true, Launch: defaultBuilderLaunch})
	if n := l.builderNote(); n != builderUnsetNote {
		t.Fatalf("no builder image on the box: note %q", n)
	}
	if s.build.Load() != nil || l.build.Ready(loops.Brief{}) {
		t.Fatal("a builder was attached with no image")
	}

	l = testLearning(t)
	dir := t.TempDir()
	l.startBuilder(&fakeBuilderMachines{}, images{"builder": "/img/builder"}, &s,
		buildConfig{Dir: filepath.Join(dir, "build"), Image: defaultBuilderImage, ImageDefault: true, Launch: filepath.Join(dir, "missing.json")})
	if n := l.builderNote(); n != builderOffNote {
		t.Fatalf("builder image without its launch file: note %q", n)
	}
	if l.build.Ready(loops.Brief{}) {
		t.Fatal("a builder was attached without its launch file")
	}
}
