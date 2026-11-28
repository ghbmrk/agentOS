package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CH-12, OWN-17

// noRoomMachines has no agent machine yet and refuses every start for
// memory.
type noRoomMachines struct{}

func (noRoomMachines) Get(id string) (vm.Machine, error) {
	return vm.Machine{}, fmt.Errorf("%w: machine %s", vm.ErrUnknown, id)
}

func (noRoomMachines) Create(context.Context, string, vm.Spec) (vm.Machine, error) {
	return vm.Machine{}, admission.ErrNoRoom
}

func (noRoomMachines) Resume(context.Context, string) error { return admission.ErrNoRoom }

// STATUS during boot says the agent is starting: before the guest plane
// has had its chance to open, and before the keeper's first try returns.
// It never says "not set up" (which asks for a restart) or names a memory
// wait the keeper has not seen (#6176).
func TestAgentStatusDuringBootSaysStarting(t *testing.T) {
	l := newLateStatus("", newCapState(""))
	if got := l.Status(); got != agentStarting {
		t.Fatalf("before the plane opens: %q, want %q", got, agentStarting)
	}

	k := newKeeper(noRoomMachines{}, "agent", testSpec)
	l.k.Store(k)
	l.settle()
	if got := l.Status(); got != agentStarting {
		t.Fatalf("before the keeper's first try: %q, want %q", got, agentStarting)
	}

	k.setStatus(k.ensure(context.Background()))
	if got := l.Status(); got != agentWaiting {
		t.Fatalf("after a try refused for memory: %q, want %q", got, agentWaiting)
	}
}

// Once start-up has had its chance and no keeper was stored, with no cause
// named, STATUS says the agent is not set up: the starting line holds only
// for the start-up window.
func TestAgentStatusAfterBootWithNoKeeperSaysNotSet(t *testing.T) {
	l := newLateStatus("", newCapState(""))
	l.settle()
	if got := l.Status(); got != agentNotSet {
		t.Fatalf("settled, no keeper: %q, want %q", got, agentNotSet)
	}
}

// A cause named before the daemon runs wins over the starting line.
func TestAgentStatusOffWinsOverStarting(t *testing.T) {
	l := newLateStatus(agentNoMachines, nil)
	if got := l.Status(); got != agentNoMachines {
		t.Fatalf("off during boot: %q, want %q", got, agentNoMachines)
	}
}

// A box with no machine runtime names that cause through caps during boot
// (machinesUnset), and STATUS keeps to that one agent line: the starting
// line does not join it (OP-9).
func TestAgentStatusCapsCauseWinsOverStarting(t *testing.T) {
	caps := newCapState("")
	caps.machinesUnset("", "")
	l := newLateStatus("", caps)
	if got := l.Status(); got != "" {
		t.Fatalf("caps names the agent during boot: %q, want no agent line", got)
	}
}

// main ends the start-up window exactly once, after every path that stores
// the keeper or names the agent's cause (#6176): called before them, a
// boot read in between says "not set up"; never called, a box with no
// keeper and no cause says "starting" for good.
func TestMainSettlesAfterEveryAgentStartPath(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var settles []token.Pos
	var last token.Pos
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" || fn.Recv != nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch recv := exprName(sel.X); {
			case recv == "agentStatus" && sel.Sel.Name == "settle":
				settles = append(settles, call.Pos())
			case recv == "agentStatus.k" && sel.Sel.Name == "Store",
				recv == "caps" && sel.Sel.Name == "agentOff":
				last = max(last, call.Pos())
			}
			return true
		})
	}
	if len(settles) != 1 {
		t.Fatalf("main calls agentStatus.settle %d times, want 1", len(settles))
	}
	if last == token.NoPos {
		t.Fatal("main stores no keeper and names no agent cause")
	}
	if settles[0] < last {
		t.Errorf("settle at %v comes before a keeper store or agent cause at %v", fset.Position(settles[0]), fset.Position(last))
	}
}

// exprName is a selector chain's dotted name, "" for anything else.
func exprName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if x := exprName(e.X); x != "" {
			return x + "." + e.Sel.Name
		}
	}
	return ""
}
