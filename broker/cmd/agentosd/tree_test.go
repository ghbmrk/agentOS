package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CAP-5, REV-5, ARC-6

type noEval struct{}

func (noEval) Run(context.Context, change.Tree, change.Probe) ([]byte, error) {
	return nil, change.ErrNotEvaluated
}

func labels(m map[string]vm.Label) func(string) (vm.Label, error) {
	return func(id string) (vm.Label, error) {
		l, ok := m[id]
		if !ok {
			return 0, vm.ErrUnknown
		}
		return l, nil
	}
}

func fetchTree(t *testing.T, lt *liveTree, machine, version string) (treeAnswer, error) {
	t.Helper()
	args, _ := json.Marshal(map[string]string{"version": version})
	text, ok, err := lt.Call(context.Background(), machine, "lin", toolTree, args)
	if !ok {
		t.Fatal("managed_tree not handled")
	}
	if err != nil {
		return treeAnswer{}, err
	}
	var a treeAnswer
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		t.Fatal(err)
	}
	return a, nil
}

// W4: the pipeline's procedures, skills and context reach the live agent
// through managed_tree. agentosd wires the tree as the pipeline's target
// for those namespaces, so the adopted tree is applied to it at start, as
// after every adoption and UNDO; nothing with authority is sent.
func TestW4AdoptedTreeReachesTheAgent(t *testing.T) {
	dir := t.TempDir()
	skillFile := []byte(`{"id":"greet"}`)
	// An earlier run adopted a skill and a grant change.
	if _, err := change.New(change.Config{
		Store:     change.FileStore{Path: filepath.Join(dir, "change.json")},
		Evaluator: noEval{},
		Initial: change.Tree{"skills/greet.json": skillFile, "procedures/p.json": []byte("p"),
			"context/c.md": []byte("c"), "grants/g.json": []byte("g")},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lt := newLiveTree(t.Logf)
	if _, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json"), Tree: lt}, false, &cfg); err != nil {
		t.Fatal(err)
	}
	lt.label = labels(map[string]vm.Label{"agent": vm.Private})
	a, err := fetchTree(t, lt, "agent", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Files) != 3 || string(a.Files["skills/greet.json"]) != string(skillFile) || a.Files["grants/g.json"] != nil {
		t.Fatalf("tree sent: %v", a.Files)
	}
	// The version is the tree's: asking with it sends nothing.
	again, err := fetchTree(t, lt, "agent", a.Version)
	if err != nil || !again.Unchanged || again.Files != nil {
		t.Fatalf("unchanged tree: %+v %v", again, err)
	}
	// An UNDO applies the namespace without the file.
	if err := (treeTarget{lt, "skills"}).Apply(change.Tree{}); err != nil {
		t.Fatal(err)
	}
	after, _ := fetchTree(t, lt, "agent", a.Version)
	if after.Unchanged || len(after.Files) != 2 || after.Files["skills/greet.json"] != nil {
		t.Fatalf("after undo: %+v", after)
	}
}

// REV-5, compile K7: the tree is derived from owner tasks, so only a
// machine already labelled private gets it. A public machine is refused
// and not raised, an unknown one too, and so is every machine before the
// machine plane opens.
func TestW4TreeReachesOnlyPrivateMachines(t *testing.T) {
	lt := newLiveTree(t.Logf)
	lt.markReady()
	treeTarget{lt, "skills"}.Apply(change.Tree{"skills/a.json": []byte("a")})
	if _, err := fetchTree(t, lt, "agent", ""); !errors.Is(err, errTreePublic) {
		t.Fatalf("before the machine plane: %v", err)
	}
	ls := map[string]vm.Label{"agent": vm.Public, "fork": vm.Private}
	lt.label = labels(ls)
	for _, m := range []string{"agent", "nobody"} {
		if _, err := fetchTree(t, lt, m, ""); !errors.Is(err, errTreePublic) {
			t.Fatalf("%s: %v", m, err)
		}
	}
	if ls["agent"] != vm.Public {
		t.Fatal("a public machine was raised")
	}
	if a, err := fetchTree(t, lt, "fork", ""); err != nil || len(a.Files) != 1 {
		t.Fatalf("private machine: %+v %v", a, err)
	}
}

// A tree past maxTreeSend is not sent in part.
func TestW4OversizeTreeIsNotSent(t *testing.T) {
	lt := newLiveTree(t.Logf)
	lt.label = labels(map[string]vm.Label{"agent": vm.Private})
	lt.markReady()
	treeTarget{lt, "context"}.Apply(change.Tree{"context/big.md": make([]byte, maxTreeSend)})
	if _, err := fetchTree(t, lt, "agent", ""); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversize: %v", err)
	}
}

// G15: the guest socket lists the question tools and managed_tree, and
// each name goes to its own set.
func TestToolSetServesEachSet(t *testing.T) {
	lt := newLiveTree(t.Logf)
	lt.label = labels(map[string]vm.Label{"agent": vm.Private})
	lt.markReady()
	q := &questions{}
	set := toolSet{nil, q, lt}
	names := map[string]bool{}
	for _, tl := range set.List() {
		names[tl["name"].(string)] = true
	}
	if !names[toolTree] || !names["owner_question"] {
		t.Fatalf("listed %v", names)
	}
	if _, ok, err := set.Call(context.Background(), "agent", "lin", toolTree, nil); !ok || err != nil {
		t.Fatalf("managed_tree: %v %v", ok, err)
	}
	if _, ok, err := set.Call(context.Background(), "agent", "lin", "owner_question", nil); !ok || err == nil {
		t.Fatalf("question tool with no book: %v %v", ok, err)
	}
	if _, ok, _ := set.Call(context.Background(), "agent", "lin", "effect_request", nil); ok {
		t.Fatal("handled a tool no set serves")
	}
}

// L3 on #120: before the pipeline has opened and applied its state, and
// with no learning plane at all, the copy is empty but is not the box's
// tree, so it is not sent: a guest mirroring it would delete every skill
// it holds.
func TestW4TreeIsNotSentUntilThePipelineOpens(t *testing.T) {
	lt := newLiveTree(t.Logf)
	lt.label = labels(map[string]vm.Label{"agent": vm.Private})
	if _, err := fetchTree(t, lt, "agent", ""); !errors.Is(err, errTreeNotReady) {
		t.Fatalf("before the pipeline: %v", err)
	}
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	if _, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json"), Tree: lt}, false, &cfg); err != nil {
		t.Fatal(err)
	}
	if a, err := fetchTree(t, lt, "agent", ""); err != nil || len(a.Files) != 0 || a.Version == "" {
		t.Fatalf("a first start's empty tree: %+v %v", a, err)
	}
}

// A target applies only its own namespace.
func TestW4TargetRefusesOtherNamespaces(t *testing.T) {
	lt := newLiveTree(t.Logf)
	if err := (treeTarget{lt, "skills"}).Apply(change.Tree{"skills/a.json": nil, "grants/g.json": []byte("g")}); err == nil {
		t.Fatal("a skills target applied a grants file")
	}
	if len(lt.files) != 0 {
		t.Fatalf("partly applied: %v", lt.files)
	}
}
