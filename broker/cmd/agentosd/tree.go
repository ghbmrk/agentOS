package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/vm"
)

// agentNamespaces are the managed tree's namespaces a guest reads (replay
// R5): what Loop 1 adopts for the agent, and nothing with authority.
var agentNamespaces = []string{"procedures", "skills", "context"}

// toolTree is the broker tool through which a guest fetches the live
// managed tree (W4). It is a broker tool over MCP (ARC-6 (b)), not a new
// service.
const toolTree = "managed_tree"

// maxTreeSend bounds one managed_tree answer. A tree past it is not sent
// at all, so a guest never runs half of one.
const maxTreeSend = 4 << 20

// liveTree is the live agent's copy of the managed tree (W4): the change
// pipeline's target for agentNamespaces, so an adoption, an UNDO or a
// restart's restore lands here, and the guest's bridge fetches it with
// managed_tree. The tree is derived from owner tasks and no file carries a
// public mark yet, so only a machine already labelled private gets it
// (REV-5, compile K7); a public machine is refused and never raised, so a
// PUBLIC task stays public. Memory only: the pipeline holds the state and
// applies it again at start.
type liveTree struct {
	mu    sync.Mutex
	files change.Tree
	// label reports a machine's label; nil (no machine plane) refuses
	// every machine.
	label func(machine string) (vm.Label, error)
	logf  func(format string, args ...any)
}

func newLiveTree(logf func(string, ...any)) *liveTree {
	return &liveTree{files: change.Tree{}, logf: logf}
}

// targets are the pipeline's targets for agentNamespaces.
func (t *liveTree) targets() map[string]change.Target {
	out := map[string]change.Target{}
	for _, ns := range agentNamespaces {
		out[ns] = treeTarget{t, ns}
	}
	return out
}

type treeTarget struct {
	t  *liveTree
	ns string
}

// Current is empty: the pipeline's own state is the record, applied at
// start (change C1).
func (g treeTarget) Current() (change.Tree, error) { return change.Tree{}, nil }

func (g treeTarget) Apply(files change.Tree) error {
	g.t.mu.Lock()
	defer g.t.mu.Unlock()
	for p := range g.t.files {
		if ns, _, _ := strings.Cut(p, "/"); ns == g.ns {
			delete(g.t.files, p)
		}
	}
	for p, b := range files {
		g.t.files[p] = append([]byte(nil), b...)
	}
	return nil
}

// treeAnswer is managed_tree's result. Version is the tree's hash; a
// caller that already holds it gets Unchanged and no files.
type treeAnswer struct {
	Version   string            `json:"version"`
	Unchanged bool              `json:"unchanged,omitempty"`
	Files     map[string][]byte `json:"files,omitempty"`
}

var errTreePublic = errors.New("the managed tree reaches only private machines; this one has had no owner data")

func (t *liveTree) List() []map[string]any {
	return []map[string]any{{
		"name": toolTree,
		"description": "Fetch the box's adopted procedures, skills and context (the managed tree). " +
			"Pass the version you hold to learn whether it changed. Only a machine that has had owner data gets it.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"version": map[string]any{"type": "string"}},
		},
	}}
}

func (t *liveTree) Call(_ context.Context, machine, _, name string, args json.RawMessage) (string, bool, error) {
	if name != toolTree {
		return "", false, nil
	}
	var a struct {
		Version string `json:"version"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return "", true, errors.New("arguments must be an object")
		}
	}
	t.mu.Lock()
	label := t.label
	t.mu.Unlock()
	if label == nil {
		return "", true, errTreePublic
	}
	// The label is read before the tree, so a tree read here was owed to
	// a machine that was private when it asked.
	if l, err := label(machine); err != nil || l != vm.Private {
		return "", true, errTreePublic
	}
	t.mu.Lock()
	files := change.Tree{}
	size := 0
	for p, b := range t.files {
		files[p] = b
		size += len(p) + len(b)
	}
	t.mu.Unlock()
	ans := treeAnswer{Version: files.Hash()}
	if ans.Version == a.Version {
		ans.Unchanged = true
	} else if size > maxTreeSend {
		t.logf("managed tree not sent to %s: %d bytes, over %d", machine, size, maxTreeSend)
		return "", true, errors.New("the managed tree is too large to send")
	} else {
		ans.Files = files
	}
	b, err := json.Marshal(ans)
	return string(b), true, err
}

// setMachines lets managed_tree read machine labels once the machine
// plane is open.
func (t *liveTree) setMachines(m *vm.Manager) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.label = func(id string) (vm.Label, error) {
		mc, err := m.Get(id)
		return mc.Label, err
	}
}

// toolSet serves several broker tool sets on one guest socket (guest
// G15), in order; a nil entry is skipped.
type toolSet []guest.Tools

func (s toolSet) List() []map[string]any {
	var out []map[string]any
	for _, t := range s {
		if t != nil {
			out = append(out, t.List()...)
		}
	}
	return out
}

func (s toolSet) Call(ctx context.Context, machine, lineage, name string, args json.RawMessage) (string, bool, error) {
	for _, t := range s {
		if t == nil {
			continue
		}
		if text, ok, err := t.Call(ctx, machine, lineage, name, args); ok {
			return text, ok, err
		}
	}
	return "", false, nil
}
