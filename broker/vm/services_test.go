package vm

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: ARC-5, OP-1, REV-5, ARC-6

// recServices records Open and Close calls.
type recServices struct {
	root   string
	mu     sync.Mutex
	open   map[string]bool
	closed []string
	opened []string
	fail   bool
}

func (s *recServices) Open(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return "", errors.New("no socket")
	}
	s.open[id] = true
	s.opened = append(s.opened, id)
	return filepath.Join(s.root, id), nil
}

func (s *recServices) Close(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, id)
	s.closed = append(s.closed, id)
}

// TestARC6EachLaunchGetsItsOwnServicesDirectory: every start, restore, and
// fork hands the runtime that machine's own services directory, never its
// source's; removal closes it (V15).
func TestARC6EachLaunchGetsItsOwnServicesDirectory(t *testing.T) {
	e := newEnv(t, 4096)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}}
	e.cfg.Services = svc
	e.open()
	ctx := context.Background()
	e.create("m1", admission.Accepted, 256)
	_, err := e.m.Checkpoint(ctx, "m1")
	must(t, err)
	_, err = e.m.Fork(ctx, "m1", []string{"f1", "f2"})
	must(t, err)
	must(t, e.m.Rebuild(ctx, "m1"))
	_, err = e.m.Fork(ctx, "f2", []string{"g1"})
	must(t, err)
	root, _ := e.m.Get("m1")
	if !strings.HasPrefix(root.Lineage, "m1.") || len(root.Lineage) != len("m1.")+12 {
		t.Fatalf("m1 lineage %q, want m1.<nonce>", root.Lineage)
	}
	for _, id := range []string{"f1", "f2", "g1"} {
		if mc, _ := e.m.Get(id); mc.Lineage != root.Lineage {
			t.Errorf("%s lineage %q, want %q", id, mc.Lineage, root.Lineage)
		}
	}
	for _, l := range e.rt.launches {
		if want := filepath.Join(svc.root, l.ID); l.Services != want {
			t.Errorf("launch of %s got services %q, want %q", l.ID, l.Services, want)
		}
	}
	must(t, e.m.Destroy(ctx, "f1"))
	if svc.open["f1"] {
		t.Fatal("destroy left f1's services open")
	}
	if !svc.open["m1"] || !svc.open["f2"] {
		t.Fatal("destroying f1 closed another machine's services")
	}
}

// TestARC6NoServicesNoStart: a machine whose services cannot be opened does
// not start, and its admission is released.
func TestARC6NoServicesNoStart(t *testing.T) {
	e := newEnv(t, 4096)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}, fail: true}
	e.cfg.Services = svc
	e.open()
	if _, err := e.m.Create(context.Background(), "m1", Spec{Image: "base", Class: admission.Accepted, MemMB: 256}); err == nil {
		t.Fatal("machine started without its services")
	}
	if len(e.rt.launches) != 0 {
		t.Fatal("runtime was started")
	}
	if len(e.m.Machines()) != 0 {
		t.Fatal("failed machine still listed")
	}
	svc.fail = false
	e.create("m1", admission.Accepted, 4096) // the whole capacity: the failed attempt released it
}

// TestOP1ReusedIDGetsANewLineage: a machine created under an ID that an
// earlier, destroyed machine used does not share its intent namespace.
func TestOP1ReusedIDGetsANewLineage(t *testing.T) {
	e := newEnv(t, 4096)
	e.open()
	first := e.create("m1", admission.Accepted, 256)
	must(t, e.m.Destroy(context.Background(), "m1"))
	second := e.create("m1", admission.Accepted, 256)
	if first.Lineage == second.Lineage {
		t.Fatalf("re-created m1 reused lineage %q", first.Lineage)
	}
}

// TestREV5DataLabelFailsClosed: model egress reads "public" only for a
// known public machine; unknown machines and private ones read "private".
func TestREV5DataLabelFailsClosed(t *testing.T) {
	e := newEnv(t, 4096)
	e.open()
	e.create("pub", admission.Accepted, 256)
	if got := e.m.DataLabel("pub"); got != "public" {
		t.Fatalf("public machine reads %q", got)
	}
	if got := e.m.DataLabel("nobody"); got != "private" {
		t.Fatalf("unknown machine reads %q, want private", got)
	}
	must(t, e.m.RaiseLabel("pub", Private))
	if got := e.m.DataLabel("pub"); got != "private" {
		t.Fatalf("raised machine reads %q", got)
	}
}
